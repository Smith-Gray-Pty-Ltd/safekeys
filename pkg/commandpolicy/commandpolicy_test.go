package commandpolicy

import "testing"

// The denylist is a backstop, not the control — these tests pin the approved
// list so a regression is visible, and its documented limits are honest.

func TestDumpersRefused(t *testing.T) {
	cases := [][]string{
		{"env"},
		{"/usr/bin/env"},
		{"printenv", "SAFEKEYS_SECRET"},
		{"set"},
		{"export"},
		{"cat", "/tmp/injected-file"},
		{"head", "/tmp/injected-file"},
		{"tail", "-n", "5", "/tmp/injected-file"},
		{"less", "/tmp/injected-file"},
		{"more", "/tmp/injected-file"},
		{"echo", "$SAFEKEYS_SECRET"},
		{"printf", "%s", "$SAFEKEYS_SECRET"},
		{"tee", "/tmp/out"},
		{"cp", "/tmp/injected-file", "/tmp/steal"},
		{"mv", "/tmp/injected-file", "/tmp/steal"},
		{"dd", "if=/tmp/injected-file"},
		{"base64"},
		{"xxd"},
		{"od"},
		{"hexdump"},
		{"strings", "/tmp/injected-file"},
	}
	for _, argv := range cases {
		if !Refuses(argv) {
			t.Errorf("Refuses(%q) = false, want true", argv)
		}
	}
}

func TestInlineInterpretersRefused(t *testing.T) {
	cases := [][]string{
		{"sh", "-c", "printenv SAFEKEYS_SECRET"},
		{"/bin/bash", "-c", "echo $SAFEKEYS_SECRET"},
		{"zsh", "-c", "env"},
		{"fish", "-c", "env"},
		{"python", "-c", "import os; print(os.environ['X'])"},
		{"python3", "-c", "import os; print(os.environ['X'])"},
		{"node", "-e", "console.log(process.env.X)"},
		{"node", "--eval", "console.log(process.env.X)"},
		{"perl", "-e", "print $ENV{X}"},
		{"ruby", "-e", "puts ENV['X']"},
		{"php", "-r", "echo getenv('X');"},
		{"awk", "BEGIN{print ENVIRON[\"X\"]}"},
		{"osascript", "-e", "do shell script \"env\""},
	}
	for _, argv := range cases {
		if !Refuses(argv) {
			t.Errorf("Refuses(%q) = false, want true", argv)
		}
	}
}

func TestLegitimateCommandsPass(t *testing.T) {
	cases := [][]string{
		{"/usr/bin/curl", "https://api.example.com/", "-H", "Authorization: Bearer $SAFEKEYS_SECRET"},
		{"/usr/bin/mycli", "--token-env", "SAFEKEYS_SECRET", "deploy"},
		{"python3", "/opt/tools/rotate.py"}, // file-based, no inline code
		{"awk", "-f", "/opt/tools/report.awk"},
		{"/bin/true"},
		{"git", "push"},
	}
	for _, argv := range cases {
		if Refuses(argv) {
			t.Errorf("Refuses(%q) = true, want false", argv)
		}
	}
}

func TestEmptyArgvRefusesNothing(t *testing.T) {
	if Refuses(nil) || Refuses([]string{}) {
		t.Fatal("empty argv must be a non-decision")
	}
}

func TestSpecMatchesArgv(t *testing.T) {
	cases := []struct {
		spec CommandSpec
		argv []string
		want bool
	}{
		{CommandSpec{Exec: "/usr/bin/curl"}, []string{"/usr/bin/curl", "https://x"}, true}, // nil args = any
		{CommandSpec{Exec: "/usr/bin/curl"}, []string{"/usr/bin/curl"}, true},              // even none
		{CommandSpec{Exec: "/usr/bin/curl"}, []string{"/bin/curl"}, false},                 // exact path
		{CommandSpec{Exec: "/usr/bin/curl", Args: []string{"https://x"}}, []string{"/usr/bin/curl", "https://x"}, true},
		{CommandSpec{Exec: "/usr/bin/curl", Args: []string{"https://x"}}, []string{"/usr/bin/curl", "https://y"}, false},
		{CommandSpec{Exec: "/usr/bin/curl", Args: []string{"*"}}, []string{"/usr/bin/curl", "anything"}, true},
		{CommandSpec{Exec: "/usr/bin/curl", Args: []string{"*"}}, []string{"/usr/bin/curl"}, false}, // arity
		{CommandSpec{Exec: "/usr/bin/curl", Args: []string{}}, []string{"/usr/bin/curl"}, true},     // exactly no args
	}
	for i, tc := range cases {
		if got := tc.spec.MatchesArgv(tc.argv); got != tc.want {
			t.Errorf("case %d: MatchesArgv(%q) = %v, want %v", i, tc.argv, got, tc.want)
		}
	}
}

func TestMatchesAny(t *testing.T) {
	specs := []CommandSpec{
		{Exec: "/usr/bin/curl", Args: []string{"https://api.example.com/*", "*"}},
		{Exec: "/usr/bin/mycli"},
	}
	if !MatchesAny(specs, []string{"/usr/bin/mycli", "run"}) {
		t.Fatal("second spec should match")
	}
	if MatchesAny(specs, []string{"/bin/cat", "/etc/passwd"}) {
		t.Fatal("nothing should match cat")
	}
}
