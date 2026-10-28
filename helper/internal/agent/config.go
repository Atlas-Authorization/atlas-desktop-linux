package agent

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
)

const (
	DefaultConfigPath = "/etc/atlas/desktop.json"
	DefaultStateDir   = "/var/lib/atlas"
)

// Config is /etc/atlas/desktop.json (written by atlas-enroll).
type Config struct {
	InstanceURL             string   `json:"instance_url"`
	PublishableKey          string   `json:"publishable_key"`
	InstanceID              string   `json:"instance_id"`
	DeviceID                string   `json:"device_id"`
	DeviceKeyID             string   `json:"device_key_id"`
	Enrolled                bool     `json:"enrolled"`
	FailOpenWhenNeverSynced *bool    `json:"fail_open_when_never_synced,omitempty"`
	EnrolledUsers           []string `json:"enrolled_users,omitempty"`
	BreakGlassAccounts      []string `json:"break_glass_accounts,omitempty"`
}

func (c *Config) Validate() error {
	u, err := url.Parse(c.InstanceURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ErrInsecureURL
	}
	if c.PublishableKey == "" || c.InstanceID == "" {
		return errors.New("config: publishable_key and instance_id are required")
	}
	if c.Enrolled && (c.DeviceID == "" || c.DeviceKeyID == "") {
		return errors.New("config: enrolled without a device")
	}
	return nil
}

func (c *Config) BaseURL() string { return strings.TrimSuffix(c.InstanceURL, "/") }

func (c *Config) FailOpen() bool { return c.FailOpenWhenNeverSynced != nil && *c.FailOpenWhenNeverSynced }

// AppliesTo: no enrolled_users means every account.
func (c *Config) AppliesTo(user string) bool {
	if len(c.EnrolledUsers) == 0 {
		return true
	}
	return contains(c.EnrolledUsers, user)
}

func (c *Config) IsBreakGlass(user string) bool { return contains(c.BreakGlassAccounts, user) }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// LoadConfig refuses a config file anyone but its owner could have written.
func LoadConfig(path string) (*Config, error) {
	if err := checkOwned(path, false); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrNotEnrolled
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		return nil, errors.New("config: malformed")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Write(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o644)
}
