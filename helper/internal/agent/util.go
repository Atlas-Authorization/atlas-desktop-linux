// Package agent is the Linux side of the Atlas workstation protocol (desktop/macos-authorization-plugin/PROTOCOL.md).
package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrRevoked     = errors.New("device revoked")
	ErrNotEnrolled = errors.New("not enrolled")
	ErrInsecureURL = errors.New("instance URL must be https")
)

// NetworkError means the server could not be reached (offline unlock may apply).
type NetworkError struct{ Msg string }

func (e *NetworkError) Error() string { return "network: " + e.Msg }

// APIError is a non-2xx answer from the server.
type APIError struct {
	Status       int
	Code         string
	DeviceStatus string
}

func (e *APIError) Error() string { return fmt.Sprintf("api status %d code %q", e.Status, e.Code) }

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64u accepts padded or unpadded base64url.
func unb64u(s string) ([]byte, error) {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func sha256b64u(s string) string { h := sha256.Sum256([]byte(s)); return b64u(h[:]) }

func ctEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// SignedMessage is the exact byte string an agent signs: atlas-desktop:v1:<purpose>:<instance>:<key id>:<nonce>[:<extra>].
func SignedMessage(purpose, instanceID, keyID, nonce string, extra *string) string {
	m := "atlas-desktop:v1:" + purpose + ":" + instanceID + ":" + keyID + ":" + nonce
	if extra != nil {
		m += ":" + *extra
	}
	return m
}

// Clock lets tests move time.
type Clock interface{ NowMs() int64 }

type SystemClock struct{}

func (SystemClock) NowMs() int64 { return time.Now().UnixMilli() }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func formatNumber(f float64) string { return fmt.Sprintf("%d", int64(f)) }
