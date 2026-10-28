package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// PamHelper is the agent side of pam_atlas.so: one process per PAM transaction, a line protocol on stdin/stdout.
// It is the same protocol as the macOS helper (PamHelper.swift):
//
//	BEGIN <user> <service>      -> ALLOW <text> | DENY <text> | CHALLENGE online=0|1 push=0|1 totp=0|1 offline=0|1 pin=0|1
//	PUSH                        -> NUMBER <digits>, then OK | REJECT <text> | UNREACHABLE
//	CODE <6 digits>             -> OK | RETRY <text> | REJECT <text> | LOCKED | UNREACHABLE
//	OFFLINE <pin|-> <6 digits>  -> OK | RETRY <text> | REJECT <text> | LOCKED
//	QUIT
type PamHelper struct {
	Cfg      *Config
	Gate     *LoginGate // nil when this machine holds no device key
	began    bool
	factors  []string
	MaxPolls int
}

func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
		if b.Len() >= 120 {
			break
		}
	}
	return b.String()
}

func validName(s string, max int) bool {
	if s == "" || len(s) > max || s[0] == '-' {
		return false
	}
	for _, r := range s {
		ok := r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '.' || r == '_' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

func reply(r Result) string {
	switch r.Outcome {
	case OutAllowed:
		return "OK"
	case OutRetry:
		return "RETRY " + clean(r.Msg)
	case OutUnreachable:
		return "UNREACHABLE"
	case OutLocked:
		return "LOCKED"
	}
	return "REJECT " + clean(r.Msg)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (h *PamHelper) has(f string) bool {
	for _, x := range h.factors {
		if x == f {
			return true
		}
	}
	return false
}

// Handle processes one command line; each reply line goes to out. It returns false when the session is over.
func (h *PamHelper) Handle(ctx context.Context, line string, out func(string)) bool {
	parts := strings.Split(line, " ")
	switch parts[0] {
	case "BEGIN":
		if h.began || len(parts) != 3 || !validName(parts[1], 63) || !validName(parts[2], 31) {
			out("DENY bad request")
			return false
		}
		h.began = true
		user := parts[1]
		if h.Gate == nil {
			switch {
			case h.Cfg.IsBreakGlass(user):
				out("ALLOW break-glass account")
			case !h.Cfg.AppliesTo(user):
				out("ALLOW account not enrolled")
			default:
				out("DENY this machine is not enrolled")
			}
			return false
		}
		d := h.Gate.Begin(ctx, user)
		switch d.Kind {
		case DecAllow:
			out("ALLOW " + clean(d.Why))
			return true
		case DecDeny:
			out("DENY " + clean(d.Why))
			return false
		}
		p := d.Prompt
		var f []string
		for _, x := range p.Factors {
			if x == "push" || x == "totp" {
				f = append(f, x)
			}
		}
		h.factors = f
		if len(f) == 0 && !p.OfflineAvailable {
			out("DENY no usable factor for this service")
			return false
		}
		out(fmt.Sprintf("CHALLENGE online=%d push=%d totp=%d offline=%d pin=%d", b2i(p.Online), b2i(h.has("push")), b2i(h.has("totp")), b2i(p.OfflineAvailable), b2i(p.PinRequired)))
		return true
	case "PUSH":
		if h.Gate == nil || !h.began || !h.has("push") || len(parts) != 1 {
			out("REJECT push unavailable")
			return true
		}
		polls := h.MaxPolls
		if polls == 0 {
			polls = 60
		}
		out(reply(h.Gate.RunPush(ctx, func(n string) { out("NUMBER " + clean(n)) }, polls)))
		return true
	case "CODE":
		if h.Gate == nil || !h.began || len(parts) != 2 || !isDigits(parts[1], 6, 6) || !h.has("totp") {
			out("REJECT bad request")
			return true
		}
		out(reply(h.Gate.VerifyCode(ctx, parts[1])))
		return true
	case "OFFLINE":
		if h.Gate == nil || !h.began || len(parts) != 3 || !isDigits(parts[2], 6, 6) || !(parts[1] == "-" || isDigits(parts[1], 6, 12)) {
			out("REJECT bad request")
			return true
		}
		pin := parts[1]
		if pin == "-" {
			pin = ""
		}
		out(reply(h.Gate.Offline(pin, parts[2])))
		return true
	case "QUIT":
		return false
	}
	out("REJECT unknown command")
	return false
}

// Serve reads commands until QUIT, EOF or an overall deadline. Anything that goes wrong ends the session without an ALLOW.
func (h *PamHelper) Serve(ctx context.Context, in io.Reader, w io.Writer) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	bw := bufio.NewWriter(w)
	say := func(s string) { _, _ = bw.WriteString(s + "\n"); _ = bw.Flush() }
	r := bufio.NewReaderSize(in, 1024)
	for {
		raw, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull || len(raw) > 255 {
			say("DENY bad request")
			return
		}
		if len(raw) > 0 || err == nil {
			if !h.Handle(ctx, strings.TrimSuffix(string(raw), "\n"), say) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
