// labserver: DPI lab server for Railway (single file).
// Starts one Xray process with many VLESS inbounds (one per test profile), a path-based
// router in front, /_lab/* measurement endpoints, and a decoy page for everything else.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ===================== test matrix =====================

// Keys holds the secrets generated on the server and shipped in the manifest.
type Keys struct {
	UUID       string `json:"uuid"`
	X25519Dec  string `json:"-"`
	X25519Enc  string `json:"x25519Enc"`
	MLKEMDec   string `json:"-"`
	MLKEMEnc   string `json:"mlkemEnc"`
	PadEntries string `json:"-"`
}

// Profile is one server-side configuration (one Xray inbound).
type Profile struct {
	ID         string `json:"id"`
	Transport  string `json:"transport"`         // ws | httpupgrade | grpc | xhttp
	Mode       string `json:"mode,omitempty"`    // xhttp only: packet-up | stream-up | stream-one
	Enc        string `json:"enc"`               // none | x25519 | mlkem | mlkem-xorpub | mlkem-random | mlkem-pad
	XOpts      string `json:"xopts,omitempty"`   // xhttp only: default | cookie | obfs | big | tokenish | getck
	PathStyle  string `json:"pathStyle"`         // lab | api | static | long
	Path       string `json:"path"`              // router prefix (xhttp/ws/httpupgrade), "/<svc>/" for grpc
	Service    string `json:"service,omitempty"` // grpc service name
	Port       int    `json:"port"`              // local inbound port (server side)
	Encryption string `json:"encryption"`        // client "encryption" string (public parts only)
	Decryption string `json:"-"`                 // server "decryption" string
	NeedsH2    bool   `json:"needsH2"`           // transport cannot work over http/1.1
	Notes      string `json:"notes,omitempty"`
}

// Manifest is what the server hands to the client.
type Manifest struct {
	Version    int       `json:"version"`
	ServerTime string    `json:"serverTime"`
	UUID       string    `json:"uuid"`
	SelfTarget string    `json:"selfTarget"` // host:port reachable from the exit (the router itself)
	Profiles   []Profile `json:"profiles"`
}

const ManifestVersion = 1

func short(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])[:8]
}

func long(id string) string {
	h := sha256.Sum256([]byte("long:" + id))
	return hex.EncodeToString(h[:])[:32]
}

func pathFor(style, id, kind string) string {
	switch style {
	case "api":
		return "/api/v2/" + short(id) + "/sync"
	case "static":
		return "/static/js/" + short(id) + ".chunk.js"
	case "long":
		return "/" + long(id)
	default:
		return "/lab/" + id
	}
}

func withMode(enc, mode string) string { return strings.Replace(enc, ".native.", "."+mode+".", 1) }

// withPadding inserts padding entries before the trailing key component.
func withPadding(enc, pad string) string {
	i := strings.LastIndex(enc, ".")
	return enc[:i] + "." + pad + enc[i:]
}

const padHeavy = "100-200-3000.50-0-300.80-0-2000"

// BuildProfiles lists every server profile. Ports are assigned from basePort.
func BuildProfiles(k Keys, basePort int) []Profile {
	type spec struct {
		tr, mode, enc, xopts, style string
	}
	var specs []spec

	// 1) transport x encryption core grid
	core := []struct{ tr, mode string }{
		{"ws", ""}, {"httpupgrade", ""}, {"grpc", ""},
		{"xhttp", "packet-up"}, {"xhttp", "stream-up"}, {"xhttp", "stream-one"},
	}
	for _, c := range core {
		for _, e := range []string{"none", "x25519", "mlkem"} {
			specs = append(specs, spec{c.tr, c.mode, e, "", "lab"})
		}
	}
	// 2) handshake obfuscation / padding variants on two representative transports
	for _, c := range []struct{ tr, mode string }{{"ws", ""}, {"xhttp", "packet-up"}} {
		for _, e := range []string{"mlkem-xorpub", "mlkem-random", "mlkem-pad"} {
			specs = append(specs, spec{c.tr, c.mode, e, "", "lab"})
		}
	}
	// 3) xhttp HTTP-shape variants (the "mimicry" dimension)
	for _, x := range []string{"cookie", "obfs", "big", "tokenish", "getck"} {
		specs = append(specs, spec{"xhttp", "packet-up", "mlkem", x, "lab"})
	}
	specs = append(specs, spec{"xhttp", "stream-up", "mlkem", "obfs", "lab"})
	// 4) URL path styles
	for _, st := range []string{"api", "static", "long"} {
		specs = append(specs, spec{"xhttp", "packet-up", "mlkem", "", st})
		specs = append(specs, spec{"ws", "", "mlkem", "", st})
	}

	var out []Profile
	for i, s := range specs {
		id := idFor(s.tr, s.mode, s.enc, s.xopts, s.style)
		p := Profile{
			ID: id, Transport: s.tr, Mode: s.mode, Enc: s.enc, XOpts: s.xopts,
			PathStyle: s.style, Port: basePort + i,
		}
		switch s.tr {
		case "grpc":
			p.Service = "lab." + short(id) + ".Stream"
			p.Path = "/" + p.Service + "/"
			p.NeedsH2 = true
		case "xhttp":
			p.Path = pathFor(s.style, id, "xhttp") + "/"
		default:
			p.Path = pathFor(s.style, id, s.tr)
		}
		p.Encryption, p.Decryption = encFor(k, s.enc)
		out = append(out, p)
	}
	return out
}

func idFor(tr, mode, enc, xopts, style string) string {
	t := map[string]string{"ws": "ws", "httpupgrade": "hu", "grpc": "grpc", "xhttp": "xh"}[tr]
	parts := []string{t}
	switch mode {
	case "packet-up":
		parts = append(parts, "pu")
	case "stream-up":
		parts = append(parts, "su")
	case "stream-one":
		parts = append(parts, "so")
	}
	parts = append(parts, enc)
	if xopts != "" {
		parts = append(parts, xopts)
	}
	if style != "lab" {
		parts = append(parts, "p"+style)
	}
	return strings.Join(parts, "-")
}

func encFor(k Keys, enc string) (client, server string) {
	switch enc {
	case "none":
		return "none", "none"
	case "x25519":
		return k.X25519Enc, k.X25519Dec
	case "mlkem":
		return k.MLKEMEnc, k.MLKEMDec
	case "mlkem-xorpub":
		return withMode(k.MLKEMEnc, "xorpub"), withMode(k.MLKEMDec, "xorpub")
	case "mlkem-random":
		return withMode(k.MLKEMEnc, "random"), withMode(k.MLKEMDec, "random")
	case "mlkem-pad":
		return withPadding(k.MLKEMEnc, padHeavy), withPadding(k.MLKEMDec, padHeavy)
	}
	return "none", "none"
}

type M = map[string]any

func xhttpSettings(p Profile, host, caseID string) M {
	s := M{"path": p.Path, "mode": p.Mode}
	if host != "" {
		s["host"] = host
	}
	switch p.XOpts {
	case "cookie":
		s["sessionIDPlacement"] = "cookie"
		s["sessionIDKey"] = "sid"
		s["seqPlacement"] = "header"
		s["seqKey"] = "X-Seq"
		s["xPaddingPlacement"] = "cookie"
		s["xPaddingKey"] = "_ga"
	case "obfs":
		s["xPaddingObfsMode"] = true
		s["xPaddingPlacement"] = "queryInHeader"
		s["xPaddingHeader"] = "Referer"
		s["xPaddingKey"] = "x_padding"
		s["xPaddingMethod"] = "tokenish"
	case "big":
		s["xPaddingBytes"] = "500-2500"
		s["serverMaxHeaderBytes"] = 32768
	case "tokenish":
		s["xPaddingMethod"] = "tokenish"
	case "getck":
		s["uplinkHTTPMethod"] = "GET"
		s["uplinkDataPlacement"] = "cookie"
		s["uplinkDataKey"] = "_d"
		s["uplinkChunkSize"] = "400-900"
		s["scMaxEachPostBytes"] = "400-900"
		s["serverMaxHeaderBytes"] = 16384
	}
	if caseID != "" {
		s["headers"] = M{"X-Lab-Case": caseID}
	}
	return s
}

// ServerConfig builds the Xray server config: one VLESS inbound per profile.
//
// selfPort is the port of the lab router (the only destination reachable through the
// tunnel unless allowInternet is set): the lab measures the tunnel against itself,
// so it does not behave as an open proxy.
func ServerConfig(uuid string, ps []Profile, access bool, selfPort int, allowInternet bool) M {
	var inbounds []M
	for _, p := range ps {
		ss := M{"network": p.Transport, "security": "none"}
		switch p.Transport {
		case "ws":
			ss["wsSettings"] = M{"path": p.Path}
		case "httpupgrade":
			ss["httpupgradeSettings"] = M{"path": p.Path}
		case "grpc":
			ss["grpcSettings"] = M{"serviceName": p.Service, "multiMode": true}
		case "xhttp":
			ss["xhttpSettings"] = xhttpSettings(p, "", "")
		}
		inbounds = append(inbounds, M{
			"tag": "in-" + p.ID, "listen": "127.0.0.1", "port": p.Port, "protocol": "vless",
			"settings":       M{"clients": []M{{"id": uuid, "email": "lab@" + p.ID}}, "decryption": p.Decryption},
			"streamSettings": ss,
		})
	}
	logc := M{"loglevel": "warning"}
	if access {
		logc["loglevel"] = "info"
	} else {
		logc["access"] = "none"
	}
	return M{
		"log":       logc,
		"inbounds":  inbounds,
		"outbounds": []M{{"protocol": "freedom", "tag": "direct", "settings": M{"finalRules": freedomRules(selfPort, allowInternet)}}},
	}
}

func freedomRules(selfPort int, allowInternet bool) []M {
	rules := []M{{"action": "allow", "network": "tcp", "port": fmt.Sprint(selfPort), "ip": []string{"127.0.0.1"}}}
	if !allowInternet {
		rules = append(rules, M{"action": "block"})
	}
	return rules
}

// ===================== server =====================

type stat struct {
	reqs, bytesIn, bytesOut, active atomic.Int64
	firstMs, lastMs                 atomic.Int64
}

func (s *stat) touch() {
	now := time.Now().UnixMilli()
	s.firstMs.CompareAndSwap(0, now)
	s.lastMs.Store(now)
}

func (s *stat) snap() map[string]any {
	return map[string]any{
		"reqs": s.reqs.Load(), "bytesIn": s.bytesIn.Load(), "bytesOut": s.bytesOut.Load(),
		"active": s.active.Load(), "firstMs": s.firstMs.Load(), "lastMs": s.lastMs.Load(),
	}
}

type route struct {
	p     Profile
	proxy *httputil.ReverseProxy
	st    *stat
	exact bool
}

type server struct {
	token      string
	uuid       string
	routes     []*route
	manifest   []byte
	selfTarget string
	logger     *slog.Logger
	randBuf    []byte

	mu    sync.Mutex
	cases map[string]*caseStat
}

type caseStat struct {
	Profile  string         `json:"profile"`
	Reqs     int64          `json:"reqs"`
	BytesIn  int64          `json:"bytesIn"`
	BytesOut int64          `json:"bytesOut"`
	FirstMs  int64          `json:"firstMs"`
	LastMs   int64          `json:"lastMs"`
	Protos   map[string]int `json:"protos"`
}

// ---------- keys ----------

type stored struct {
	UUID      string `json:"uuid"`
	X25519Dec string `json:"x25519Dec"`
	X25519Enc string `json:"x25519Enc"`
	MLKEMDec  string `json:"mlkemDec"`
	MLKEMEnc  string `json:"mlkemEnc"`
}

var kvRe = regexp.MustCompile(`"(decryption|encryption)":\s*"([^"]+)"`)

func genKeys(xray string) (Keys, error) {
	out, err := exec.Command(xray, "vlessenc").Output()
	if err != nil {
		return Keys{}, fmt.Errorf("xray vlessenc: %w", err)
	}
	m := kvRe.FindAllStringSubmatch(string(out), -1)
	if len(m) != 4 {
		return Keys{}, fmt.Errorf("unexpected vlessenc output (%d pairs)", len(m))
	}
	return Keys{
		UUID: newUUID(), X25519Dec: m[0][2], X25519Enc: m[1][2], MLKEMDec: m[2][2], MLKEMEnc: m[3][2],
	}, nil
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func loadOrGenKeys(xray, dir string) (Keys, error) {
	path := filepath.Join(dir, "lab-keys.json")
	if b, err := os.ReadFile(path); err == nil {
		var s stored
		if json.Unmarshal(b, &s) == nil && s.UUID != "" && s.MLKEMEnc != "" {
			return Keys{UUID: s.UUID, X25519Dec: s.X25519Dec, X25519Enc: s.X25519Enc, MLKEMDec: s.MLKEMDec, MLKEMEnc: s.MLKEMEnc}, nil
		}
	}
	k, err := genKeys(xray)
	if err != nil {
		return k, err
	}
	b, _ := json.Marshal(stored{k.UUID, k.X25519Dec, k.X25519Enc, k.MLKEMDec, k.MLKEMEnc})
	_ = os.WriteFile(path, b, 0o600)
	return k, nil
}

// ---------- response recorder ----------

type rec struct {
	http.ResponseWriter
	status int
	n      int64
}

func (r *rec) WriteHeader(c int) {
	if r.status == 0 {
		r.status = c
	}
	r.ResponseWriter.WriteHeader(c)
}
func (r *rec) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	n, err := r.ResponseWriter.Write(b)
	r.n += int64(n)
	return n, err
}
func (r *rec) Flush()                      { _ = http.NewResponseController(r.ResponseWriter).Flush() }
func (r *rec) Unwrap() http.ResponseWriter { return r.ResponseWriter }

type countBody struct {
	io.ReadCloser
	n *atomic.Int64
	c *atomic.Int64
}

func (c *countBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	if c.c != nil {
		c.c.Add(int64(n))
	}
	return n, err
}

// ---------- router ----------

func mkTransport(h2c bool) *http.Transport {
	t := &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 128, IdleConnTimeout: 90 * time.Second}
	if h2c {
		t.Protocols = new(http.Protocols)
		t.Protocols.SetUnencryptedHTTP2(true)
	}
	return t
}

func (s *server) buildRoutes(ps []Profile) {
	h1 := mkTransport(false)
	h2 := mkTransport(true)
	for _, p := range ps {
		p := p
		target := "127.0.0.1:" + strconv.Itoa(p.Port)
		useH2 := p.Transport == "xhttp" || p.Transport == "grpc"
		rt := &route{p: p, st: &stat{}, exact: p.Transport == "ws" || p.Transport == "httpupgrade"}
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = target
				pr.Out.Host = pr.In.Host
			},
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				s.logger.Warn("upstream error", "profile", p.ID, "err", err.Error())
				w.WriteHeader(http.StatusBadGateway)
			},
		}
		if useH2 {
			rp.Transport = h2
		} else {
			rp.Transport = h1
		}
		rt.proxy = rp
		s.routes = append(s.routes, rt)
	}
	sort.Slice(s.routes, func(i, j int) bool { return len(s.routes[i].p.Path) > len(s.routes[j].p.Path) })
}

func (s *server) match(path string) *route {
	for _, rt := range s.routes {
		if rt.exact {
			if path == rt.p.Path {
				return rt
			}
			continue
		}
		if strings.HasPrefix(path, rt.p.Path) || path == strings.TrimSuffix(rt.p.Path, "/") {
			return rt
		}
	}
	return nil
}

func caseOf(r *http.Request) string {
	if c := r.Header.Get("X-Lab-Case"); c != "" {
		return c
	}
	if ua := r.Header.Get("User-Agent"); strings.HasPrefix(ua, "labcase/") {
		return strings.TrimPrefix(ua, "labcase/")
	}
	return ""
}

func (s *server) caseTouch(id, profile, proto string) *caseStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs := s.cases[id]
	if cs == nil {
		if len(s.cases) > 5000 {
			return &caseStat{Protos: map[string]int{}}
		}
		cs = &caseStat{Profile: profile, FirstMs: time.Now().UnixMilli(), Protos: map[string]int{}}
		s.cases[id] = cs
	}
	cs.Reqs++
	cs.LastMs = time.Now().UnixMilli()
	cs.Protos[proto]++
	return cs
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rw := &rec{ResponseWriter: w}
	kind, id := "decoy", ""
	var in, out atomic.Int64
	switch {
	case strings.HasPrefix(r.URL.Path, "/_lab/"):
		kind = "lab"
		s.lab(rw, r)
	default:
		if rt := s.match(r.URL.Path); rt != nil {
			kind, id = "tunnel", rt.p.ID
			cid := caseOf(r)
			if cid != "" {
				s.caseTouch(cid, rt.p.ID, r.Proto)
			}
			rt.st.reqs.Add(1)
			rt.st.active.Add(1)
			rt.st.touch()
			if rt.p.Transport == "xhttp" && r.ProtoMajor == 1 {
				_ = http.NewResponseController(rw).EnableFullDuplex()
			}
			r.Body = &countBody{ReadCloser: r.Body, n: &in, c: &rt.st.bytesIn}
			s.logger.Info("tunnel-start", "profile", rt.p.ID, "case", cid, "proto", r.Proto, "method", r.Method)
			rt.proxy.ServeHTTP(rw, r)
			rt.st.active.Add(-1)
			rt.st.bytesOut.Add(rw.n)
			out.Store(rw.n)
			rt.st.touch()
			if cid != "" {
				s.mu.Lock()
				if cs := s.cases[cid]; cs != nil {
					cs.BytesIn += in.Load()
					cs.BytesOut += rw.n
					cs.LastMs = time.Now().UnixMilli()
				}
				s.mu.Unlock()
			}
		} else {
			decoy(rw, r)
		}
	}
	if kind == "lab" && r.URL.Path == "/_lab/ping" {
		return // keep logs quiet
	}
	s.logger.Info("req", "kind", kind, "profile", id, "case", caseOf(r), "method", r.Method,
		"path", trunc(r.URL.Path, 60), "proto", r.Proto, "status", rw.status, "out", rw.n, "in", in.Load(),
		"ms", time.Since(start).Milliseconds(), "ua", trunc(r.UserAgent(), 50))
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func decoy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>Status</title></head><body style="font-family:sans-serif;max-width:40em;margin:4em auto"><h1>Service status</h1><p>All systems operational.</p></body></html>`)
		return
	}
	http.NotFound(w, r)
}

// ---------- /_lab endpoints ----------

func (s *server) auth(r *http.Request) bool {
	t := r.Header.Get("X-Lab-Token")
	if t == "" {
		t = r.URL.Query().Get("t")
	}
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func qint(r *http.Request, k string, def, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(k))
	if err != nil || v < 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func (s *server) lab(w *rec, r *http.Request) {
	ep := strings.TrimPrefix(r.URL.Path, "/_lab/")
	if ep == "ping" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"t":%d,"proto":%q}`+"\n", time.Now().UnixNano(), r.Proto)
		return
	}
	if !s.auth(r) {
		http.NotFound(w, r)
		return
	}
	switch ep {
	case "manifest":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.manifest)
	case "down":
		n := qint(r, "bytes", 1<<20, 200<<20)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Header().Set("Cache-Control", "no-store")
		rc := http.NewResponseController(w)
		sent := 0
		for sent < n {
			c := len(s.randBuf)
			if n-sent < c {
				c = n - sent
			}
			if _, err := w.Write(s.randBuf[:c]); err != nil {
				return
			}
			sent += c
			if sent%(256<<10) < c {
				_ = rc.Flush()
			}
		}
	case "up":
		t0 := time.Now()
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"bytes":%d,"ms":%d}`+"\n", n, time.Since(t0).Milliseconds())
	case "stream":
		iv := qint(r, "interval", 2000, 60000)
		secs := qint(r, "secs", 60, 3600)
		size := qint(r, "size", 64, 65536)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		rc := http.NewResponseController(w)
		t0 := time.Now()
		tk := time.NewTicker(time.Duration(iv) * time.Millisecond)
		defer tk.Stop()
		for i := 0; time.Since(t0) < time.Duration(secs)*time.Second; i++ {
			line := fmt.Sprintf("tick %d %d", i, time.Since(t0).Milliseconds())
			pad := size - len(line) - 1
			if pad < 0 {
				pad = 0
			}
			if _, err := fmt.Fprintf(w, "%s%s\n", line, strings.Repeat(".", pad)); err != nil {
				return
			}
			_ = rc.Flush()
			select {
			case <-tk.C:
			case <-r.Context().Done():
				return
			}
		}
	case "echo":
		// Shows which headers the edge adds/keeps. Client address headers are dropped
		// so shared logs do not contain the user's IP.
		h := map[string][]string{}
		for k, v := range r.Header {
			lk := strings.ToLower(k)
			if lk == "x-lab-token" || lk == "forwarded" || lk == "true-client-ip" || lk == "cf-connecting-ip" ||
				strings.HasPrefix(lk, "x-forwarded-") || lk == "x-real-ip" || lk == "x-envoy-external-address" {
				continue
			}
			h[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proto": r.Proto, "host": r.Host, "headers": h, "tls": r.TLS != nil,
			"serverTime": time.Now().UTC().Format(time.RFC3339Nano),
		})
	case "stats":
		s.mu.Lock()
		cs := make(map[string]*caseStat, len(s.cases))
		for k, v := range s.cases {
			c := *v
			cs[k] = &c
		}
		s.mu.Unlock()
		rs := map[string]any{}
		for _, rt := range s.routes {
			rs[rt.p.ID] = rt.st.snap()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"routes": rs, "cases": cs, "serverTime": time.Now().UnixMilli()})
		if r.URL.Query().Get("reset") == "1" {
			s.mu.Lock()
			s.cases = map[string]*caseStat{}
			s.mu.Unlock()
		}
	default:
		http.NotFound(w, r)
	}
}

// ---------- xray supervisor ----------

func superviseXray(ctx context.Context, bin, cfg string, logger *slog.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, bin, "run", "-c", cfg)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		t0 := time.Now()
		err := cmd.Run()
		logger.Warn("xray exited", "err", fmt.Sprint(err), "after", time.Since(t0).String())
		if time.Since(t0) > time.Minute {
			backoff = time.Second
		} else if backoff < 30*time.Second {
			backoff *= 2
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
	}
}

func waitPort(port int, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 300*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	port := env("PORT", "8080")
	xray := env("XRAY_BIN", "xray")
	stateDir := env("LAB_STATE_DIR", os.TempDir())
	token := os.Getenv("LAB_TOKEN")
	if token == "" {
		b := make([]byte, 12)
		rand.Read(b)
		token = hex.EncodeToString(b)
		logger.Warn("LAB_TOKEN not set; generated one for this run", "token", token)
	}
	basePort := 20000
	if v, err := strconv.Atoi(env("LAB_BASE_PORT", "20000")); err == nil {
		basePort = v
	}

	keys, err := loadOrGenKeys(xray, stateDir)
	if err != nil {
		logger.Error("keys", "err", err.Error())
		os.Exit(1)
	}
	profiles := BuildProfiles(keys, basePort)
	if f := os.Getenv("LAB_PROFILES"); f != "" {
		re, err := regexp.Compile(f)
		if err != nil {
			logger.Error("LAB_PROFILES regexp", "err", err.Error())
			os.Exit(1)
		}
		var keep []Profile
		for _, p := range profiles {
			if re.MatchString(p.ID) {
				keep = append(keep, p)
			}
		}
		profiles = keep
	}

	pnum, _ := strconv.Atoi(port)
	selfTarget := "127.0.0.1:" + port
	m := Manifest{
		Version: ManifestVersion, ServerTime: time.Now().UTC().Format(time.RFC3339),
		UUID: keys.UUID, SelfTarget: selfTarget, Profiles: profiles,
	}
	mb, _ := json.MarshalIndent(m, "", "  ")

	s := &server{token: token, uuid: keys.UUID, manifest: mb, selfTarget: selfTarget, logger: logger, cases: map[string]*caseStat{}}
	s.randBuf = make([]byte, 32<<10)
	rand.Read(s.randBuf)
	s.buildRoutes(profiles)

	cfg := ServerConfig(keys.UUID, profiles, os.Getenv("LAB_XRAY_ACCESS") == "1", pnum, os.Getenv("LAB_ALLOW_INTERNET") == "1")
	cb, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(stateDir, "lab-xray.json")
	if err := os.WriteFile(cfgPath, cb, 0o600); err != nil {
		logger.Error("write config", "err", err.Error())
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go superviseXray(ctx, xray, cfgPath, logger)
	if len(profiles) > 0 && waitPort(profiles[0].Port, 15*time.Second) {
		logger.Info("xray ready", "profiles", len(profiles))
	} else {
		logger.Warn("xray not ready yet (will keep serving decoy + /_lab)")
	}

	srv := &http.Server{Addr: ":" + port, Handler: s, ReadHeaderTimeout: 15 * time.Second}
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetHTTP1(true)
	srv.Protocols.SetUnencryptedHTTP2(true)
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	logger.Info("labserver listening", "port", pnum, "profiles", len(profiles))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("listen", "err", err.Error())
		os.Exit(1)
	}
}
