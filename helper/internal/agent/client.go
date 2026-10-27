package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Client speaks desktop/macos-authorization-plugin/PROTOCOL.md. Every call past enrolment is signed with the device key.
type Client struct {
	Cfg  *Config
	Key  *DeviceKey
	HTTP *http.Client
}

func NewClient(cfg *Config, key *DeviceKey) *Client {
	return &Client{Cfg: cfg, Key: key, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type SyncResponse struct {
	Status         string   `json:"status"`
	Required       bool     `json:"required"`
	AllowedFactors []string `json:"allowed_factors"`
	Offline        struct {
		Enabled     bool    `json:"enabled"`
		GraceHours  int     `json:"grace_hours"`
		PinRequired bool    `json:"pin_required"`
		PinSet      bool    `json:"pin_set"`
		KeepCache   bool    `json:"keep_cache"`
		BundleValid bool    `json:"bundle_valid"`
		Bundle      *Bundle `json:"bundle"`
	} `json:"offline"`
	ServerTime int64 `json:"server_time"`
}

type Challenge struct {
	ID          string
	NumberMatch string
}

type EnrollResponse struct {
	Device struct {
		ID string `json:"id"`
	} `json:"device"`
	BundleMacKey string `json:"bundle_mac_key"`
	OfflineOtpURI string `json:"offline_otp_uri"`
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	if c.Cfg.Validate() != nil {
		return ErrInsecureURL
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Cfg.BaseURL()+"/v1/client/desktop_mfa/"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("X-Publishable-Key", c.Cfg.PublishableKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &NetworkError{"request failed"}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &NetworkError{"read failed"}
	}
	if resp.StatusCode/100 == 2 {
		if out == nil {
			return nil
		}
		if json.Unmarshal(data, out) != nil {
			return &APIError{Status: 0, Code: "malformed_response"}
		}
		return nil
	}
	e := &APIError{Status: resp.StatusCode}
	var o struct {
		Errors []struct {
			Code string `json:"code"`
			Meta struct {
				DeviceStatus string `json:"device_status"`
			} `json:"meta"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &o) == nil && len(o.Errors) > 0 {
		e.Code, e.DeviceStatus = o.Errors[0].Code, o.Errors[0].Meta.DeviceStatus
	}
	if resp.StatusCode == 403 && e.DeviceStatus == "revoked" {
		return ErrRevoked
	}
	return e
}

func (c *Client) nonce(ctx context.Context) (string, error) {
	var o struct {
		Nonce string `json:"nonce"`
	}
	if err := c.post(ctx, "nonce", map[string]string{"device_id": c.Cfg.DeviceID}, &o); err != nil {
		return "", err
	}
	if o.Nonce == "" {
		return "", &APIError{Code: "malformed_response"}
	}
	return o.Nonce, nil
}

func (c *Client) sig(purpose, nonce string, extra *string) (string, error) {
	return c.Key.Sign(SignedMessage(purpose, c.Cfg.InstanceID, c.Cfg.DeviceID, nonce, extra))
}

func (c *Client) Enroll(ctx context.Context, code, pin, hostname, agentVersion string) (*EnrollResponse, error) {
	jwk := c.Key.PublicJWK()
	s, err := c.Key.Sign(SignedMessage("enroll", c.Cfg.InstanceID, jwk.X, code, nil))
	if err != nil {
		return nil, err
	}
	body := map[string]any{"code": code, "public_key": jwk, "signature": s, "hostname": hostname, "platform": "linux", "agent_version": agentVersion}
	if pin != "" {
		body["pin"] = pin
	}
	var r EnrollResponse
	if err := c.post(ctx, "enroll", body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) Sync(ctx context.Context, held string) (*SyncResponse, error) {
	n, err := c.nonce(ctx)
	if err != nil {
		return nil, err
	}
	extra := "-"
	if held != "" {
		extra = held
	}
	s, err := c.sig("sync", n, &extra)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"device_id": c.Cfg.DeviceID, "nonce": n, "signature": s}
	if held != "" {
		body["held_bundle_id"] = held
	}
	var r SyncResponse
	if err := c.post(ctx, "sync", body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) StartChallenge(ctx context.Context, factor string) (*Challenge, error) {
	n, err := c.nonce(ctx)
	if err != nil {
		return nil, err
	}
	s, err := c.sig("challenge", n, &factor)
	if err != nil {
		return nil, err
	}
	var o struct {
		ID          string `json:"id"`
		NumberMatch any    `json:"number_match"`
	}
	if err := c.post(ctx, "challenges", map[string]any{"device_id": c.Cfg.DeviceID, "nonce": n, "signature": s, "factor": factor}, &o); err != nil {
		return nil, err
	}
	if o.ID == "" {
		return nil, &APIError{Code: "malformed_response"}
	}
	ch := &Challenge{ID: o.ID}
	switch v := o.NumberMatch.(type) {
	case string:
		ch.NumberMatch = v
	case float64:
		ch.NumberMatch = formatNumber(v)
	}
	return ch, nil
}

// Verify returns "pending" | "verified" | "failed". A wrong code (422) is an *APIError with Status 422.
func (c *Client) Verify(ctx context.Context, challengeID, code string) (string, error) {
	s, err := c.sig("verify", challengeID, nil)
	if err != nil {
		return "", err
	}
	body := map[string]any{"device_id": c.Cfg.DeviceID, "signature": s}
	if code != "" {
		body["code"] = code
	}
	var o struct {
		Status string `json:"status"`
	}
	if err := c.post(ctx, "challenges/"+challengeID+"/verify", body, &o); err != nil {
		return "", err
	}
	if o.Status == "" {
		return "", &APIError{Code: "malformed_response"}
	}
	return o.Status, nil
}

func (c *Client) SetPIN(ctx context.Context, pin string) error {
	n, err := c.nonce(ctx)
	if err != nil {
		return err
	}
	extra := sha256b64u(pin)
	s, err := c.sig("pin", n, &extra)
	if err != nil {
		return err
	}
	return c.post(ctx, "pin", map[string]any{"device_id": c.Cfg.DeviceID, "nonce": n, "signature": s, "pin": pin}, nil)
}

func (c *Client) Report(ctx context.Context, events []OfflineEvent) error {
	if len(events) > 200 {
		events = events[:200]
	}
	p, err := json.Marshal(events)
	if err != nil {
		return err
	}
	n, err := c.nonce(ctx)
	if err != nil {
		return err
	}
	extra := sha256b64u(string(p))
	s, err := c.sig("report", n, &extra)
	if err != nil {
		return err
	}
	return c.post(ctx, "report", map[string]any{"device_id": c.Cfg.DeviceID, "nonce": n, "signature": s, "payload": string(p)}, nil)
}
