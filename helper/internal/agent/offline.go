package agent

type OfflineEvent struct {
	At       int64  `json:"at"`
	Outcome  string `json:"outcome"`
	BundleID string `json:"bundle_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type offlineState struct {
	HighWaterMs   int64          `json:"high_water_ms"`
	LastTotpStep  int64          `json:"last_totp_step"`
	Failures      int            `json:"failures"`
	LockedUntilMs int64          `json:"locked_until_ms"`
	Queue         []OfflineEvent `json:"queue"`
}

type OfflineResult int

const (
	OfflineAllowed OfflineResult = iota
	OfflineWrongPIN
	OfflineWrongCode
	OfflineLocked
	OfflineExpired
	OfflineClockTampered
	OfflineInvalid
)

const (
	offlineKey         = "offline_state"
	maxOfflineFailures = 5
	offlineLockMs      = 15 * 60_000
	offlineSkewMs      = 5 * 60_000
)

type OfflineUnlock struct {
	Store *Store
	Clock Clock
}

func (o *OfflineUnlock) load() offlineState {
	s := offlineState{LastTotpStep: -1}
	if !o.Store.Load(offlineKey, &s) {
		s = offlineState{LastTotpStep: -1}
	}
	return s
}

func (o *OfflineUnlock) Queue() []OfflineEvent { return o.load().Queue }

func (o *OfflineUnlock) RemoveQueued(n int) {
	unlock, err := o.Store.Lock()
	if err != nil {
		return
	}
	defer unlock()
	s := o.load()
	if n > len(s.Queue) {
		n = len(s.Queue)
	}
	s.Queue = s.Queue[n:]
	_ = o.Store.Save(offlineKey, s)
}

// Record appends one event (kept at most 1000).
func (o *OfflineUnlock) Record(at int64, outcome, bundle, reason string) {
	unlock, err := o.Store.Lock()
	if err != nil {
		return
	}
	defer unlock()
	s := o.load()
	s.Queue = appendEvent(s.Queue, OfflineEvent{at, outcome, bundle, reason})
	_ = o.Store.Save(offlineKey, s)
}

func appendEvent(q []OfflineEvent, e OfflineEvent) []OfflineEvent {
	q = append(q, e)
	if len(q) > 1000 {
		q = q[len(q)-1000:]
	}
	return q
}

// Attempt never allows unless the state change was persisted first (fail closed), and it holds the store lock so two
// concurrent logins cannot both spend one TOTP step or dodge the failure counter.
func (o *OfflineUnlock) Attempt(p *BundlePlain, pin, code string) (OfflineResult, int64) {
	unlock, err := o.Store.Lock()
	if err != nil {
		return OfflineInvalid, 0
	}
	defer unlock()
	now := o.Clock.NowMs()
	s := o.load()
	fail := func(r OfflineResult, reason string) (OfflineResult, int64) {
		s.Queue = appendEvent(s.Queue, OfflineEvent{now, "failure", p.BundleID, reason})
		_ = o.Store.Save(offlineKey, s)
		return r, s.LockedUntilMs
	}
	if s.LockedUntilMs > now {
		return fail(OfflineLocked, "locked")
	}
	if s.LockedUntilMs != 0 {
		s.LockedUntilMs, s.Failures = 0, 0
	}
	hw := s.HighWaterMs
	if p.IssuedAt > hw {
		hw = p.IssuedAt
	}
	if now < hw-offlineSkewMs {
		return fail(OfflineClockTampered, "clock")
	}
	if now > s.HighWaterMs {
		s.HighWaterMs = now
	}
	if now >= p.ExpiresAt {
		return fail(OfflineExpired, "expired")
	}
	pinOK := !p.PinRequired || (pin != "" && p.Pin != nil && p.Pin.Verify(pin))
	step, codeOK := totpVerify(code, p.TOTP, now, s.LastTotpStep)
	if pinOK && codeOK {
		s.LastTotpStep, s.Failures = step, 0
		s.Queue = appendEvent(s.Queue, OfflineEvent{At: now, Outcome: "success", BundleID: p.BundleID})
		if o.Store.Save(offlineKey, s) != nil {
			return OfflineInvalid, 0
		}
		return OfflineAllowed, 0
	}
	s.Failures++
	res := OfflineWrongCode
	if !pinOK {
		res = OfflineWrongPIN
	}
	if s.Failures >= maxOfflineFailures {
		s.LockedUntilMs, s.Failures, res = now+offlineLockMs, 0, OfflineLocked
	}
	reason := "code"
	if !pinOK {
		reason = "pin"
	}
	s.Queue = appendEvent(s.Queue, OfflineEvent{At: now, Outcome: "failure", BundleID: p.BundleID, Reason: reason})
	if o.Store.Save(offlineKey, s) != nil {
		return OfflineInvalid, 0
	}
	return res, s.LockedUntilMs
}
