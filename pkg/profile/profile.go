// Package profile gates development conveniences behind an explicit
// environment declaration.
//
// Several development paths are deliberately convenient and deliberately
// unsafe: a KEK in a plain file, a fixed key-store root token, an env-var
// signing seed, revocation checks switched off. Each is appropriate on a
// laptop and unacceptable on a host that holds real secrets. Rather than rely
// on an operator remembering which of them to avoid, a production start refuses
// them outright.
//
// The switch is SAFEKEYS_PROFILE. Anything other than "production" is treated
// as development, so the guard is opt-in and a misconfigured operator sees the
// safe behaviour only when they ask for it. That direction is deliberate: a
// typo in the variable must not silently relax security, and it does not, since
// the default remains the permissive development mode — the guard's job is to
// make production reject shortcuts, not to make development impossible.
package profile

import (
	"fmt"
	"os"
	"strings"
)

// Name is the environment this process believes it is running in.
type Name string

const (
	// Dev is the default: development conveniences are permitted.
	Dev Name = "dev"
	// Production refuses every development credential path.
	Production Name = "production"
)

// EnvVar is the variable that selects the profile.
const EnvVar = "SAFEKEYS_PROFILE"

// Current reports the active profile. It is resolved from the environment on
// each call rather than cached, so tests can set it with t.Setenv.
func Current() Name {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(EnvVar)), string(Production)) {
		return Production
	}
	return Dev
}

// IsProduction reports whether the process is in the production profile.
func IsProduction() bool { return Current() == Production }

// Check records a refusal reason. A caller collects the reasons it finds and
// reports them together, so an operator fixing a config sees every problem in
// one pass rather than one restart at a time.
type Check struct {
	reasons []string
}

// Refuse records that a development-only setting is active under the production
// profile. It is a no-op in development, so callers can state the rule
// unconditionally next to the setting it governs.
func (c *Check) Refuse(active bool, reason string) {
	if active && IsProduction() {
		c.reasons = append(c.reasons, reason)
	}
}

// Fail returns an error naming every refusal, or nil when the profile is
// satisfied. Callers should treat a non-nil error as fatal at startup: a
// service that cannot be configured safely must not serve.
func (c *Check) Fail() error {
	if len(c.reasons) == 0 {
		return nil
	}
	return fmt.Errorf("production profile refuses this configuration:\n  - %s\n"+
		"set these explicitly for production, or unset %s for development",
		strings.Join(c.reasons, "\n  - "), EnvVar)
}
