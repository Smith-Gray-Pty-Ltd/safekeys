package profile_test

import (
	"testing"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/pkg/profile"
)

// TestDefaultIsDev proves the guard is opt-in: without the variable the
// permissive development mode is active, so nothing changes for contributors.
func TestDefaultIsDev(t *testing.T) {
	t.Setenv(profile.EnvVar, "")
	if profile.IsProduction() {
		t.Fatal("an unset profile was treated as production")
	}
}

// TestTypoDoesNotRelaxSecurity proves a misspelled profile keeps development
// mode rather than being coerced into something unexpected.
func TestTypoDoesNotRelaxSecurity(t *testing.T) {
	t.Setenv(profile.EnvVar, "prod")
	if profile.IsProduction() {
		t.Fatal("a non-exact value selected the production profile")
	}
}

// TestProductionDetected proves the exact value selects the strict profile.
func TestProductionDetected(t *testing.T) {
	t.Setenv(profile.EnvVar, "production")
	if !profile.IsProduction() {
		t.Fatal("the production value did not select the production profile")
	}
}

// TestRefuseOnlyInProduction is the core contract: a development-only setting
// is tolerated in dev and fatal in production.
func TestRefuseOnlyInProduction(t *testing.T) {
	t.Setenv(profile.EnvVar, "dev")
	var devCheck profile.Check
	devCheck.Refuse(true, "insecure keystore enabled")
	if err := devCheck.Fail(); err != nil {
		t.Fatalf("development profile rejected a development setting: %v", err)
	}

	t.Setenv(profile.EnvVar, "production")
	var prodCheck profile.Check
	prodCheck.Refuse(true, "insecure keystore enabled")
	if err := prodCheck.Fail(); err == nil {
		t.Fatal("production profile accepted a development setting")
	}
}

// TestInactiveSettingNeverRefused proves the guard only fires for the setting
// it is told about, so it cannot fail a correctly configured production start.
func TestInactiveSettingNeverRefused(t *testing.T) {
	t.Setenv(profile.EnvVar, "production")
	var c profile.Check
	c.Refuse(false, "insecure keystore enabled")
	if err := c.Fail(); err != nil {
		t.Fatalf("an inactive setting was refused: %v", err)
	}
}
