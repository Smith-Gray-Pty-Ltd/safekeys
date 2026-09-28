//go:build darwin

package credential

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// FromKeychain reads a credential from the macOS Keychain (service, account).
//
// It returns ok=false when the item does not exist (exit 44); any other
// failure — including a denied ACL prompt — is an error, so callers fail
// closed rather than falling back to a weaker source. This is the dev-custody
// path for the token signing seed (safekeys/dev-key-custody): the item is
// created by scripts/migrate-dev-keys.sh with its access restricted to the
// control-plane binary.
func FromKeychain(service, account string) (string, bool, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", service, "-a", account, "-w")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 44 {
			return "", false, nil
		}
		return "", false, fmt.Errorf("keychain: read %s/%s: %w", service, account, err)
	}
	return strings.TrimSuffix(out.String(), "\n"), true, nil
}

// ToKeychain creates or updates a Keychain item (service, account) with the
// given value.
func ToKeychain(service, account, value string) error {
	cmd := exec.Command("security", "add-generic-password",
		"-s", service, "-a", account, "-w", value, "-U")
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain: write %s/%s: %w: %s", service, account, err, errOut.String())
	}
	return nil
}
