// atlas-enroll: enrols this machine with an admin-issued code (dsk_...), creating a root-only device key.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Atlas-Authorization/atlas-desktop-linux/helper/internal/agent"
)

func fail(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func main() {
	url := flag.String("instance-url", "", "https URL of the Atlas instance")
	pk := flag.String("publishable-key", "", "publishable key")
	iid := flag.String("instance-id", "", "instance id (ins_...)")
	code := flag.String("code", os.Getenv("ATLAS_ENROLL_CODE"), "enrolment code (or ATLAS_ENROLL_CODE)")
	pin := flag.String("pin", os.Getenv("ATLAS_ENROLL_PIN"), "offline PIN, 6-12 digits (or ATLAS_ENROLL_PIN; prompted when empty)")
	users := flag.String("users", "", "comma-separated local accounts the policy applies to (default: all)")
	breakGlass := flag.String("break-glass", "", "comma-separated local accounts that skip Atlas (keep one!)")
	cfgPath := flag.String("config", agent.DefaultConfigPath, "config file to write")
	stateDir := flag.String("state-dir", agent.DefaultStateDir, "state directory")
	flag.Parse()
	if *url == "" || *pk == "" || *iid == "" || *code == "" {
		fmt.Fprintln(os.Stderr, "usage: atlas-enroll --instance-url URL --publishable-key PK --instance-id INS --code CODE [--pin PIN] [--users a,b] [--break-glass admin]")
		os.Exit(2)
	}
	if os.Geteuid() != 0 && *stateDir == agent.DefaultStateDir {
		fail("run as root: the device key is stored under %s", *stateDir)
	}
	if *pin == "" && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Offline PIN (6-12 digits, empty for none): ")
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		*pin = string(b)
	}
	cfg := &agent.Config{InstanceURL: *url, PublishableKey: *pk, InstanceID: *iid, DeviceKeyID: "device"}
	if err := cfg.Validate(); err != nil {
		fail("enrol failed: %v", err)
	}
	if *users != "" {
		cfg.EnrolledUsers = strings.Split(*users, ",")
	}
	if *breakGlass != "" {
		cfg.BreakGlassAccounts = strings.Split(*breakGlass, ",")
	}
	store := agent.NewStore(*stateDir)
	key, err := agent.GenerateDeviceKey(store)
	if err != nil {
		fail("enrol failed: %v", err)
	}
	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r, err := agent.NewClient(cfg, key).Enroll(ctx, *code, *pin, host, "0.1.0")
	if err != nil {
		store.Delete("device.key") // a key the server never saw is useless
		fail("enrol failed: %v", err)
	}
	if err := store.Set("bundle_mac_key", []byte(r.BundleMacKey)); err != nil {
		fail("enrol failed: %v", err)
	}
	cfg.DeviceID, cfg.Enrolled = r.Device.ID, true
	if err := cfg.Write(*cfgPath); err != nil {
		fail("enrol failed: %v", err)
	}
	fmt.Println("enrolled device", r.Device.ID)
	if r.OfflineOtpURI != "" {
		fmt.Println("Offline authenticator URI (shown once, add it to your authenticator app):\n" + r.OfflineOtpURI)
	}
	if st, err := agent.RunSync(ctx, agent.NewClient(cfg, key), store, agent.SystemClock{}); err == nil {
		fmt.Printf("initial sync ok: required=%v\n", st.Required != nil && *st.Required)
	}
}
