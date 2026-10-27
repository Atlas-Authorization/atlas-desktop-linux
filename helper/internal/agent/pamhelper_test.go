package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Fatalf("line %d: got %q want prefix %q (all %q)", i, got[i], want[i], got)
		}
	}
}

func TestBeginValidation(t *testing.T) {
	e := newEnv(t)
	for _, l := range []string{"BEGIN alice", "BEGIN -alice sshd", "BEGIN al ice sshd", "BEGIN alice ssh/d", "BEGIN a;b sshd", "HELLO", "BEGIN alice sshd extra"} {
		eq(t, e.session(l), "DENY bad request")
	}
	eq(t, e.session("BEGIN alice sshd", "BEGIN alice sshd"), "CHALLENGE", "DENY bad request")
	eq(t, e.session("CODE 123456"), "REJECT bad request") // before BEGIN
	eq(t, e.session("BEGIN alice sshd\nCODE 123456\n"+strings.Repeat("A", 300)), "CHALLENGE", "OK", "DENY bad request")
}

func TestNoGateCases(t *testing.T) {
	cfg := &Config{InstanceURL: "https://x.example", PublishableKey: "k", InstanceID: "i", BreakGlassAccounts: []string{"root-admin"}, EnrolledUsers: []string{"alice"}}
	run := func(user string) []string {
		var out bytes.Buffer
		(&PamHelper{Cfg: cfg}).Serve(context.Background(), strings.NewReader("BEGIN "+user+" sudo\n"), &out)
		return strings.Split(strings.TrimSpace(out.String()), "\n")
	}
	eq(t, run("root-admin"), "ALLOW break-glass")
	eq(t, run("bob"), "ALLOW account not enrolled")
	eq(t, run("alice"), "DENY this machine is not enrolled")
}

func TestMfaNotRequiredAllows(t *testing.T) {
	e := newEnv(t)
	e.f.required = false
	eq(t, e.session("BEGIN alice sudo"), "ALLOW MFA not required")
}

func TestTotpFlow(t *testing.T) {
	e := newEnv(t)
	eq(t, e.session("BEGIN alice sudo", "CODE 111111", "CODE 123456"),
		"CHALLENGE online=1 push=1 totp=1 offline=1 pin=1", "RETRY incorrect code", "OK")
	eq(t, e.session("BEGIN alice sudo", "CODE abc"), "CHALLENGE", "REJECT bad request")
}

func TestPushFlow(t *testing.T) {
	e := newEnv(t)
	e.f.pushPolls = 2
	eq(t, e.session("BEGIN alice sshd", "PUSH"), "CHALLENGE", "NUMBER 47", "OK")
	e.f.pushDenied = true
	eq(t, e.session("BEGIN alice sshd", "PUSH"), "CHALLENGE", "NUMBER 47", "REJECT denied on phone")
}

func TestOfflineUnlock(t *testing.T) {
	e := newEnv(t)
	eq(t, e.session("BEGIN alice sudo"), "CHALLENGE online=1") // online sync caches state + bundle
	e.f.srv.Close()                                              // now the server is unreachable
	// No unlock while offline without the PIN.
	eq(t, e.session("BEGIN alice sudo", "OFFLINE - 877905"), "CHALLENGE online=0 push=0 totp=0 offline=1 pin=1", "RETRY")
	eq(t, e.session("BEGIN alice sudo", "OFFLINE 24681357 877905"), "CHALLENGE online=0", "OK")
	// The same TOTP step cannot be used twice (replay).
	eq(t, e.session("BEGIN alice sudo", "OFFLINE 24681357 877905"), "CHALLENGE", "RETRY")
	// Offline unlock refuses a PUSH or CODE request: those need the server.
	eq(t, e.session("BEGIN alice sudo", "PUSH"), "CHALLENGE", "REJECT push unavailable")
}

func TestOfflineLockoutAndExpiry(t *testing.T) {
	e := newEnv(t)
	e.session("BEGIN alice sudo")
	e.f.srv.Close()
	args := []string{"BEGIN alice sudo"}
	for i := 0; i < 5; i++ {
		args = append(args, "OFFLINE 24681357 000000")
	}
	got := e.session(args...)
	if got[len(got)-1] != "LOCKED" {
		t.Fatalf("expected LOCKED after five failures: %q", got)
	}
	// Locked even with the right answers.
	eq(t, e.session("BEGIN alice sudo", "OFFLINE 24681357 877905"), "CHALLENGE", "LOCKED")
	// After the lock lapses the correct answers work again.
	e.clock.ms += 16 * 60_000
	eq(t, e.session("BEGIN alice sudo", "OFFLINE 24681357 "+codeAt(t, e, e.clock.ms)), "CHALLENGE", "OK")
	// A bundle past its expiry is not offered at all.
	e.clock.ms = e.f.v.Bundle.ExpiresAt + 1
	eq(t, e.session("BEGIN alice sudo"), "DENY offline and no valid offline bundle")
}

func codeAt(t *testing.T, e *env, ms int64) string {
	sec, _ := base32Decode(e.f.v.TOTP.Secret)
	return totpCode(sec, ms/1000/30)
}

func TestOfflineClockRollbackRefused(t *testing.T) {
	e := newEnv(t)
	e.session("BEGIN alice sudo")
	e.f.srv.Close()
	e.clock.ms += 3600_000
	eq(t, e.session("BEGIN alice sudo", "OFFLINE 24681357 "+codeAt(t, e, e.clock.ms)), "CHALLENGE", "OK")
	e.clock.ms -= 3600_000 // clock set back an hour
	eq(t, e.session("BEGIN alice sudo", "OFFLINE 24681357 "+codeAt(t, e, e.clock.ms)), "CHALLENGE", "REJECT system clock is wrong")
}

func TestOfflineEventsReportedOnNextSync(t *testing.T) {
	e := newEnv(t)
	e.session("BEGIN alice sudo")
	srv := e.f.srv
	srv.Close()
	e.session("BEGIN alice sudo", "OFFLINE 24681357 000000")
	// Server back (a new one on a new address).
	e2 := newFakeServer(t, e.f.v)
	e.cfg.InstanceURL = e2.srv.URL
	e.gate.Client.HTTP = e2.srv.Client()
	e.session("BEGIN alice sudo")
	if len(e2.reports) != 1 || len(e2.reports[0]) == 0 || e2.reports[0][0].Outcome != "failure" {
		t.Fatalf("offline events not reported: %+v", e2.reports)
	}
	if q := (&OfflineUnlock{Store: e.store, Clock: e.clock}).Queue(); len(q) != 0 {
		t.Fatalf("queue not cleared: %+v", q)
	}
}

func TestRevokedWipesBundleAndDenies(t *testing.T) {
	e := newEnv(t)
	e.session("BEGIN alice sudo")
	var st GateState
	if !e.store.Load(gateStateKey, &st) || st.Bundle == nil {
		t.Fatal("bundle should be cached")
	}
	e.f.revoked = true
	eq(t, e.session("BEGIN alice sudo"), "DENY device revoked")
	e.store.Load(gateStateKey, &st)
	if st.Bundle != nil || st.Required == nil || !*st.Required {
		t.Fatalf("revoked state wrong: %+v", st)
	}
	// Even with the server gone, the wiped state cannot be used offline.
	e.f.srv.Close()
	eq(t, e.session("BEGIN alice sudo"), "DENY device revoked")
}

func TestNeverSyncedFailsClosedUnlessConfigured(t *testing.T) {
	e := newEnv(t)
	e.f.srv.Close()
	eq(t, e.session("BEGIN alice sudo"), "DENY MFA state unknown")
	yes := true
	e.cfg.FailOpenWhenNeverSynced = &yes
	eq(t, e.session("BEGIN alice sudo"), "ALLOW never synced, fail-open configured")
}

func TestCachedRequirementSurvivesOffline(t *testing.T) {
	e := newEnv(t)
	e.f.withBundle = false
	e.session("BEGIN alice sudo")
	e.f.srv.Close()
	// MFA was required, no bundle: offline login is refused, never password-only.
	eq(t, e.session("BEGIN alice sudo"), "DENY offline and no valid offline bundle")
}

func TestStoreRefusesLoosePermissions(t *testing.T) {
	s := newStore(t)
	if err := s.Set("x", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("x"); !ok {
		t.Fatal("should read")
	}
	if err := os.Chmod(filepath.Join(s.Dir, "x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("x"); ok {
		t.Fatal("world-writable state file was trusted")
	}
	_ = os.Chmod(filepath.Join(s.Dir, "x"), 0o600)
	link := filepath.Join(s.Dir, "link")
	_ = os.Symlink(filepath.Join(s.Dir, "x"), link)
	if _, ok := s.Get("link"); ok {
		t.Fatal("symlink was followed")
	}
}

func TestEnrolAgainstFakeServer(t *testing.T) {
	v, _ := loadVectors(t)
	f := newFakeServer(t, v)
	store := newStore(t)
	key, err := GenerateDeviceKey(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateDeviceKey(store); err == nil {
		t.Fatal("second key must not overwrite the first")
	}
	reopened, err := OpenDeviceKey(store)
	if err != nil || reopened.PublicJWK() != key.PublicJWK() {
		t.Fatal("key did not round trip")
	}
	cfg := &Config{InstanceURL: f.srv.URL, PublishableKey: "pk_test", InstanceID: f.instanceID, DeviceKeyID: "device"}
	c := NewClient(cfg, key)
	c.HTTP = f.srv.Client()
	r, err := c.Enroll(context.Background(), "dsk_code", "24681357", "host", "0.1.0")
	if err != nil || r.Device.ID != "ddv_TESTVECTOR" || r.BundleMacKey != v.MacKey {
		t.Fatalf("enrol: %+v %v", r, err)
	}
	if f.enrolled == nil || *f.enrolled != key.PublicJWK() {
		t.Fatal("server did not see our public key")
	}
	cfg.InstanceURL = "http://insecure.example"
	if _, err := c.Enroll(context.Background(), "dsk_code", "", "h", "0"); err != ErrInsecureURL {
		t.Fatalf("plain http must be refused, got %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "desktop.json")
	good := &Config{InstanceURL: "https://auth.example.com", PublishableKey: "pk", InstanceID: "ins", DeviceID: "ddv", DeviceKeyID: "device", Enrolled: true}
	if err := good.Write(p); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o666)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("writable config accepted")
	}
	_ = os.Chmod(p, 0o644)
	bad := *good
	bad.InstanceURL = "http://auth.example.com"
	_ = bad.Write(p)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("http config accepted")
	}
	if _, err := LoadConfig(filepath.Join(d, "missing.json")); err != ErrNotEnrolled {
		t.Fatalf("missing config: %v", err)
	}
}
