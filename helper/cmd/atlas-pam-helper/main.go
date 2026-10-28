// atlas-pam-helper serve: the agent behind pam_atlas.so. Reads commands on stdin, answers on stdout.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Atlas-Authorization/atlas-desktop-linux/helper/internal/agent"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "check" {
		os.Exit(check(os.Args[2:]))
	}
	if len(os.Args) != 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: atlas-pam-helper serve | check [--config PATH] [--state-dir DIR] [--allow-no-break-glass]")
		os.Exit(2)
	}
	cfg, err := agent.LoadConfig(agent.DefaultConfigPath)
	if err != nil {
		fmt.Println("DENY Atlas is not configured")
		os.Exit(1)
	}
	store := agent.NewStore(agent.DefaultStateDir)
	h := &agent.PamHelper{Cfg: cfg}
	if cfg.Enrolled {
		if key, err := agent.OpenDeviceKey(store); err == nil {
			h.Gate = agent.NewLoginGate(cfg, key, store, agent.NewClient(cfg, key), agent.SystemClock{})
		}
	}
	h.Serve(context.Background(), os.Stdin, os.Stdout)
}

// check is what the installer runs before it touches a PAM stack: the config must be valid and enrolled, the device key must
// open, and a break-glass account must exist, or every login would be refused.
func check(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := fs.String("config", agent.DefaultConfigPath, "config file")
	stateDir := fs.String("state-dir", agent.DefaultStateDir, "state directory")
	noBG := fs.Bool("allow-no-break-glass", false, "do not require a break-glass account")
	_ = fs.Parse(args)
	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check failed: config:", err)
		return 1
	}
	if !cfg.Enrolled {
		fmt.Fprintln(os.Stderr, "check failed: this machine is not enrolled (run atlas-enroll)")
		return 1
	}
	if _, err := agent.OpenDeviceKey(agent.NewStore(*stateDir)); err != nil {
		fmt.Fprintln(os.Stderr, "check failed: device key:", err)
		return 1
	}
	if len(cfg.BreakGlassAccounts) == 0 && !*noBG {
		fmt.Fprintln(os.Stderr, "check failed: no break_glass_accounts in the config. Create a dedicated local admin and list it (atlas-enroll --break-glass NAME), or pass --allow-no-break-glass")
		return 1
	}
	fmt.Println("ok")
	return 0
}
