package agent

import (
	"context"
	"errors"
	"time"
)

const (
	gateStateKey = "gate_state"
	macKeyName   = "bundle_mac_key"
)

// GateState is the last good sync result: it lets an offline workstation know whether MFA was required.
type GateState struct {
	Required       *bool    `json:"required"`
	AllowedFactors []string `json:"allowed_factors"`
	OfflineEnabled bool     `json:"offline_enabled"`
	PinRequired    bool     `json:"pin_required"`
	Revoked        bool     `json:"revoked"`
	LastSyncMs     int64    `json:"last_sync_ms"`
	Bundle         *Bundle  `json:"bundle"`
}

func macKey(s *Store) ([]byte, bool) {
	b, ok := s.Get(macKeyName)
	if !ok {
		return nil, false
	}
	k, err := unb64u(string(b))
	return k, err == nil
}

// RunSync is one sync round trip: updates the cached state, replaces or wipes the bundle, then uploads queued offline events.
func RunSync(ctx context.Context, c *Client, s *Store, clock Clock) (*GateState, error) {
	var st GateState
	s.Load(gateStateKey, &st)
	held := ""
	if st.Bundle != nil {
		held = st.Bundle.BundleID
	}
	resp, err := c.Sync(ctx, held)
	if errors.Is(err, ErrRevoked) {
		t := true
		st.Revoked, st.Bundle, st.Required = true, nil, &t
		_ = s.Save(gateStateKey, st)
		return &st, ErrRevoked
	}
	if err != nil {
		return nil, err
	}
	st.Revoked = resp.Status == "revoked"
	r := resp.Required
	st.Required = &r
	st.AllowedFactors = resp.AllowedFactors
	st.OfflineEnabled = resp.Offline.Enabled
	st.PinRequired = resp.Offline.PinRequired
	st.LastSyncMs = clock.NowMs()
	if st.Revoked || !resp.Offline.KeepCache || !resp.Offline.Enabled {
		st.Bundle = nil
	} else if b := resp.Offline.Bundle; b != nil {
		if mk, ok := macKey(s); ok && b.MacValid(mk, c.Cfg.DeviceID) {
			st.Bundle = b
		}
	}
	if err := s.Save(gateStateKey, st); err != nil {
		return nil, err
	}
	if st.Revoked {
		return &st, ErrRevoked
	}
	off := &OfflineUnlock{Store: s, Clock: clock}
	if q := off.Queue(); len(q) > 0 {
		if c.Report(ctx, q) == nil {
			n := len(q)
			if n > 200 {
				n = 200
			}
			off.RemoveQueued(n)
		}
	}
	return &st, nil
}

type Outcome int

const (
	OutAllowed Outcome = iota
	OutRetry
	OutRejected
	OutUnreachable
	OutLocked
)

// Result carries the outcome and a short, safe message.
type Result struct {
	Outcome Outcome
	Msg     string
}

type DecisionKind int

const (
	DecAllow DecisionKind = iota
	DecDeny
	DecChallenge
)

type Prompt struct {
	Online           bool
	Factors          []string
	OfflineAvailable bool
	PinRequired      bool
}

type Decision struct {
	Kind   DecisionKind
	Why    string
	Prompt Prompt
}

type LoginGate struct {
	Cfg    *Config
	Key    *DeviceKey
	Store  *Store
	Client *Client
	Clock  Clock
	Sleep  func(time.Duration)

	state     GateState
	Online    bool
	totpChall string
}

func NewLoginGate(cfg *Config, key *DeviceKey, store *Store, client *Client, clock Clock) *LoginGate {
	return &LoginGate{Cfg: cfg, Key: key, Store: store, Client: client, Clock: clock, Sleep: time.Sleep}
}

var supportedFactors = map[string]bool{"push": true, "totp": true}

// Begin decides from a fresh sync when reachable, else from cached state. Defaults to deny. The PAM module has already
// seen the password accepted by the module before it in the stack (or the admin set no_password).
func (g *LoginGate) Begin(ctx context.Context, user string) Decision {
	off := &OfflineUnlock{Store: g.Store, Clock: g.Clock}
	if g.Cfg.IsBreakGlass(user) {
		off.Record(g.Clock.NowMs(), "success", "", "break_glass:"+user)
		return Decision{Kind: DecAllow, Why: "break-glass account"}
	}
	if !g.Cfg.AppliesTo(user) {
		return Decision{Kind: DecAllow, Why: "account not enrolled"}
	}
	if !g.Cfg.Enrolled || g.Cfg.DeviceID == "" {
		if g.Cfg.FailOpen() {
			return Decision{Kind: DecAllow, Why: "not enrolled, fail-open configured"}
		}
		return Decision{Kind: DecDeny, Why: "device not enrolled"}
	}
	g.state = GateState{}
	g.Store.Load(gateStateKey, &g.state)
	st, err := RunSync(ctx, g.Client, g.Store, g.Clock)
	switch {
	case errors.Is(err, ErrRevoked):
		return Decision{Kind: DecDeny, Why: "device revoked"}
	case err == nil:
		g.state, g.Online = *st, true
	default:
		g.Online = false
	}
	if g.state.Revoked {
		return Decision{Kind: DecDeny, Why: "device revoked"}
	}
	if g.state.Required == nil {
		if g.Cfg.FailOpen() {
			return Decision{Kind: DecAllow, Why: "never synced, fail-open configured"}
		}
		return Decision{Kind: DecDeny, Why: "MFA state unknown"}
	}
	if !*g.state.Required {
		return Decision{Kind: DecAllow, Why: "MFA not required"}
	}
	var factors []string
	for _, f := range g.state.AllowedFactors {
		if supportedFactors[f] {
			factors = append(factors, f)
		}
	}
	p := Prompt{Online: g.Online, OfflineAvailable: g.offlineAvailable(), PinRequired: g.state.PinRequired}
	if g.Online {
		p.Factors = factors
	}
	if len(p.Factors) == 0 && !p.OfflineAvailable {
		if g.Online {
			return Decision{Kind: DecDeny, Why: "no usable factor"}
		}
		return Decision{Kind: DecDeny, Why: "offline and no valid offline bundle"}
	}
	return Decision{Kind: DecChallenge, Prompt: p}
}

func (g *LoginGate) offlineAvailable() bool {
	b := g.state.Bundle
	if !g.state.OfflineEnabled || b == nil {
		return false
	}
	mk, ok := macKey(g.Store)
	return ok && b.MacValid(mk, g.Cfg.DeviceID) && g.Clock.NowMs() < b.ExpiresAt
}

func (g *LoginGate) classify(err error) Result {
	var api *APIError
	var nerr *NetworkError
	switch {
	case errors.Is(err, ErrRevoked):
		return Result{OutRejected, "device revoked"}
	case errors.As(err, &nerr), errors.Is(err, ErrInsecureURL):
		g.Online = false
		return Result{OutUnreachable, ""}
	case errors.As(err, &api) && api.Status == 422:
		return Result{OutRetry, "incorrect code"}
	case errors.As(err, &api) && api.Status == 429:
		return Result{OutRejected, "too many attempts"}
	}
	return Result{OutRejected, "verification failed"}
}

// RunPush calls onNumber with the number to match, then polls every 2 s until verified or failed.
func (g *LoginGate) RunPush(ctx context.Context, onNumber func(string), maxPolls int) Result {
	c, err := g.Client.StartChallenge(ctx, "push")
	if err != nil {
		return g.classify(err)
	}
	if c.NumberMatch != "" {
		onNumber(c.NumberMatch)
	}
	for i := 0; i < maxPolls; i++ {
		if ctx.Err() != nil {
			return Result{OutRejected, "cancelled"}
		}
		s, err := g.Client.Verify(ctx, c.ID, "")
		if err != nil {
			return g.classify(err)
		}
		switch s {
		case "verified":
			return Result{OutAllowed, ""}
		case "failed":
			return Result{OutRejected, "denied on phone"}
		}
		g.Sleep(2 * time.Second)
	}
	return Result{OutRejected, "timed out"}
}

func (g *LoginGate) VerifyCode(ctx context.Context, code string) Result {
	if !isDigits(code, 6, 6) {
		return Result{OutRetry, "enter the 6-digit code"}
	}
	if g.totpChall == "" {
		c, err := g.Client.StartChallenge(ctx, "totp")
		if err != nil {
			return g.classify(err)
		}
		g.totpChall = c.ID
	}
	s, err := g.Client.Verify(ctx, g.totpChall, code)
	if err != nil {
		r := g.classify(err)
		if r.Outcome != OutRetry {
			g.totpChall = ""
		}
		return r
	}
	switch s {
	case "verified":
		return Result{OutAllowed, ""}
	case "failed":
		g.totpChall = ""
		return Result{OutRejected, "code rejected"}
	}
	return Result{OutRetry, "incorrect code"}
}

// Offline unlock: only while the server is unreachable, with a valid unexpired bundle.
func (g *LoginGate) Offline(pin, code string) Result {
	b := g.state.Bundle
	if g.Online || !g.offlineAvailable() || b == nil {
		return Result{OutRejected, "offline unlock unavailable"}
	}
	p, err := b.Open(g.Key)
	if err != nil || p.BundleID != b.BundleID || p.DeviceID != g.Cfg.DeviceID {
		return Result{OutRejected, "offline bundle unreadable"}
	}
	res, _ := (&OfflineUnlock{Store: g.Store, Clock: g.Clock}).Attempt(p, pin, code)
	switch res {
	case OfflineAllowed:
		return Result{OutAllowed, ""}
	case OfflineWrongPIN, OfflineWrongCode:
		return Result{OutRetry, "incorrect PIN or code"}
	case OfflineLocked:
		return Result{OutLocked, ""}
	case OfflineExpired:
		return Result{OutRejected, "offline bundle expired"}
	case OfflineClockTampered:
		return Result{OutRejected, "system clock is wrong"}
	}
	return Result{OutRejected, "offline unlock failed"}
}
