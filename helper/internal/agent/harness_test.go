package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ ms int64 }

func (c *fakeClock) NowMs() int64 { return c.ms }

func newStore(t *testing.T) *Store {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return NewStore(d)
}

// fakeServer is a minimal Atlas desktop_mfa server that checks every signature against the device key.
type fakeServer struct {
	mu          sync.Mutex
	t           *testing.T
	srv         *httptest.Server
	v           *vectors
	instanceID  string
	required    bool
	revoked     bool
	withBundle  bool
	verifyCodes map[string]string // code -> "ok"; any other code -> 422
	pushPolls   int               // pending answers before verified
	pushDenied  bool
	reports     [][]OfflineEvent
	nonces      map[string]bool
	n           int
	enrolled    *JWK
	challenges  int
}

func newFakeServer(t *testing.T, v *vectors) *fakeServer {
	f := &fakeServer{t: t, v: v, instanceID: "ins_TESTVECTOR", required: true, withBundle: true, verifyCodes: map[string]string{"123456": "ok"}, nonces: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) errJSON(w http.ResponseWriter, status int, code, devStatus string) {
	w.WriteHeader(status)
	m := map[string]any{"code": code}
	if devStatus != "" {
		m["meta"] = map[string]string{"device_status": devStatus}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{m}})
}

func (f *fakeServer) checkSig(body map[string]any, purpose, nonce string, extra *string) bool {
	keyID, _ := body["device_id"].(string)
	sig, _ := body["signature"].(string)
	return VerifyP1363(f.v.Public, SignedMessage(purpose, f.instanceID, keyID, nonce, extra), sig)
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Publishable-Key") != "pk_test" {
		f.errJSON(w, 401, "invalid_key", "")
		return
	}
	var body map[string]any
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &body)
	path := strings.TrimPrefix(r.URL.Path, "/v1/client/desktop_mfa/")
	w.Header().Set("Content-Type", "application/json")
	useNonce := func() (string, bool) {
		n, _ := body["nonce"].(string)
		if !f.nonces[n] {
			f.errJSON(w, 401, "bad_nonce", "")
			return "", false
		}
		delete(f.nonces, n)
		return n, true
	}
	if f.revoked && path != "enroll" {
		f.errJSON(w, 403, "forbidden", "revoked")
		return
	}
	switch {
	case path == "enroll":
		pk, _ := json.Marshal(body["public_key"])
		var jwk JWK
		_ = json.Unmarshal(pk, &jwk)
		code, _ := body["code"].(string)
		sig, _ := body["signature"].(string)
		if body["platform"] != "linux" || !VerifyP1363(jwk, SignedMessage("enroll", f.instanceID, jwk.X, code, nil), sig) {
			f.errJSON(w, 401, "verification_failed", "")
			return
		}
		f.enrolled = &jwk
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"device": map[string]string{"id": "ddv_TESTVECTOR"}, "bundle_mac_key": f.v.MacKey, "offline_otp_uri": "otpauth://totp/x"})
	case path == "nonce":
		f.n++
		n := "nonce-" + string(rune('a'+f.n%26)) + strings.Repeat("x", f.n)
		f.nonces[n] = true
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{"nonce": n})
	case path == "sync":
		n, ok := useNonce()
		if !ok {
			return
		}
		held, _ := body["held_bundle_id"].(string)
		extra := "-"
		if held != "" {
			extra = held
		}
		if !f.checkSig(body, "sync", n, &extra) {
			f.errJSON(w, 401, "verification_failed", "")
			return
		}
		off := map[string]any{"enabled": true, "grace_hours": 72, "pin_required": true, "pin_set": true, "keep_cache": true, "bundle_valid": true}
		if f.withBundle {
			off["bundle"] = map[string]any{"bundle_id": f.v.Bundle.BundleID, "generation": f.v.Bundle.Generation, "issued_at": 1800000000000, "expires_at": f.v.Bundle.ExpiresAt, "sealed": f.v.Bundle.Sealed, "mac": f.v.Bundle.Mac}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "active", "required": f.required, "allowed_factors": []string{"push", "totp", "passkey"}, "offline": off, "server_time": 1800000000000})
	case path == "challenges":
		n, ok := useNonce()
		if !ok {
			return
		}
		factor, _ := body["factor"].(string)
		if !f.checkSig(body, "challenge", n, &factor) {
			f.errJSON(w, 401, "verification_failed", "")
			return
		}
		f.challenges++
		resp := map[string]any{"id": "dlc_" + factor, "factor": factor}
		if factor == "push" {
			resp["number_match"] = 47
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(resp)
	case strings.HasPrefix(path, "challenges/") && strings.HasSuffix(path, "/verify"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "challenges/"), "/verify")
		if !f.checkSig(body, "verify", id, nil) {
			f.errJSON(w, 401, "verification_failed", "")
			return
		}
		if id == "dlc_push" {
			switch {
			case f.pushDenied:
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "failed"})
			case f.pushPolls > 0:
				f.pushPolls--
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			default:
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
			}
			return
		}
		code, _ := body["code"].(string)
		if f.verifyCodes[code] != "ok" {
			f.errJSON(w, 422, "invalid_code", "")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
	case path == "report":
		n, ok := useNonce()
		if !ok {
			return
		}
		p, _ := body["payload"].(string)
		extra := sha256b64u(p)
		if !f.checkSig(body, "report", n, &extra) {
			f.errJSON(w, 401, "verification_failed", "")
			return
		}
		var ev []OfflineEvent
		_ = json.Unmarshal([]byte(p), &ev)
		f.reports = append(f.reports, ev)
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(ev)})
	default:
		f.errJSON(w, 404, "not_found", "")
	}
}

type env struct {
	t     *testing.T
	f     *fakeServer
	cfg   *Config
	key   *DeviceKey
	store *Store
	clock *fakeClock
	gate  *LoginGate
	h     *PamHelper
}

func newEnv(t *testing.T) *env {
	v, key := loadVectors(t)
	f := newFakeServer(t, v)
	cfg := &Config{InstanceURL: f.srv.URL, PublishableKey: "pk_test", InstanceID: f.instanceID, DeviceID: "ddv_TESTVECTOR", DeviceKeyID: "device", Enrolled: true}
	store := newStore(t)
	if err := store.Set(macKeyName, []byte(v.MacKey)); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{ms: 1800000000000}
	client := NewClient(cfg, key)
	client.HTTP = f.srv.Client()
	g := NewLoginGate(cfg, key, store, client, clock)
	g.Sleep = func(time.Duration) {}
	return &env{t: t, f: f, cfg: cfg, key: key, store: store, clock: clock, gate: g, h: &PamHelper{Cfg: cfg, Gate: g}}
}

// session feeds lines to a fresh helper and returns its replies (the gate, store and server persist across sessions).
func (e *env) session(lines ...string) []string {
	e.t.Helper()
	g := NewLoginGate(e.cfg, e.key, e.store, e.gate.Client, e.clock)
	g.Sleep = func(time.Duration) {}
	h := &PamHelper{Cfg: e.cfg, Gate: g}
	var out bytes.Buffer
	h.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out)
	return strings.Split(strings.TrimSpace(out.String()), "\n")
}
