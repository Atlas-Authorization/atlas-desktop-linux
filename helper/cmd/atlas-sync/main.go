// atlas-sync: one sync round trip (run by the systemd timer): refreshes the cached MFA state and offline bundle and uploads queued offline events.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Atlas-Authorization/atlas-desktop-linux/helper/internal/agent"
)

func main() {
	cfgPath := flag.String("config", agent.DefaultConfigPath, "config file")
	stateDir := flag.String("state-dir", agent.DefaultStateDir, "state directory")
	flag.Parse()
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil || !cfg.Enrolled {
		fmt.Fprintln(os.Stderr, "sync failed: this machine is not enrolled")
		os.Exit(1)
	}
	store := agent.NewStore(*stateDir)
	key, err := agent.OpenDeviceKey(store)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sync failed:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := agent.RunSync(ctx, agent.NewClient(cfg, key), store, agent.SystemClock{})
	if err == agent.ErrRevoked {
		fmt.Fprintln(os.Stderr, "device revoked; offline cache wiped")
		os.Exit(3)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sync failed:", err)
		os.Exit(1)
	}
	fmt.Printf("synced: required=%v offline_bundle=%v\n", st.Required != nil && *st.Required, st.Bundle != nil)
}
