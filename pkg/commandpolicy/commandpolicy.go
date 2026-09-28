// Package commandpolicy implements the command dimension of resolve-time
// policy (safekeys/output-control): backstop refusal of known secret-dumping
// commands, and matching of argv against operator allowlist specifications.
//
// The denylist is a BACKSTOP, not the control. The controls are the command
// allowlist and output redaction. A denylist cannot enumerate every
// exfiltration vector — it exists so that an operator who has not yet written
// an allowlist still does not get the laziest injection for free, and the
// documentation says so rather than claiming it is complete.
//
// The list applies to CLI and SDK resolves only. MCP-initiated resolves
// require an explicit allowlist outright and never reach this list: the model
// authors the command, so "not on the denylist" must never be sufficient
// there.
package commandpolicy

import "strings"

// CommandSpec is one allowed command: an executable path pattern plus
// argument patterns. Every field is a glob in path.Match syntax — `*` matches
// any run of non-separator characters, so `https://api.example.com/*` matches
// any path on that host, and a bare `*` matches any single argument. A spec
// with a nil Args matches the executable with ANY arguments; an empty
// non-nil Args matches the executable with NO arguments.
type CommandSpec struct {
	Exec string   `json:"exec"`
	Args []string `json:"args,omitempty"`
}

// MatchesArgv reports whether argv satisfies the spec.
func (c CommandSpec) MatchesArgv(argv []string) bool {
	if len(argv) == 0 || !globMatch(c.Exec, argv[0]) {
		return false
	}
	if c.Args == nil {
		return true
	}
	if len(argv)-1 != len(c.Args) {
		return false
	}
	for i, want := range c.Args {
		if !globMatch(want, argv[i+1]) {
			return false
		}
	}
	return true
}

// globMatch reports whether s matches pattern. Patterns support `*` (any run
// of characters, INCLUDING separators — this is not path.Match semantics: an
// argument like /tmp/stolen.txt must match *), `?` (any single character),
// and character classes. A pattern without metacharacters is an exact
// compare. Custom rather than path.Match because path.Match's `*` stops at
// `/`, which would make `*` useless for matching absolute-path arguments.
func globMatch(pattern, s string) bool {
	if pattern == s {
		return true
	}
	return globHere(pattern, s)
}

// globHere matches without separator semantics: * consumes anything.
func globHere(p, s string) bool {
	// Iterative two-pointer glob with backtracking on the last '*'.
	var starP, starS = -1, -1
	i, j := 0, 0
	for j < len(s) {
		if i < len(p) {
			switch p[i] {
			case '*':
				starP, starS = i, j
				i++
				continue
			case '?':
				i++
				j++
				continue
			case '[':
				if end := classEnd(p[i:]); end > 0 {
					if matchClass(p[i:i+end], s[j]) {
						i += end
						j++
						continue
					}
				} else if p[i] == s[j] {
					i++
					j++
					continue
				}
			default:
				if p[i] == s[j] {
					i++
					j++
					continue
				}
			}
		}
		if starP >= 0 {
			// Backtrack: let the last '*' consume one more character.
			starS++
			i = starP + 1
			j = starS
			continue
		}
		return false
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	return i == len(p)
}

// classEnd returns the length of a `[...]` class at the start of p, 0 if
// unterminated.
func classEnd(p string) int {
	if len(p) < 2 {
		return 0
	}
	i := 1
	if p[i] == '^' || p[i] == '!' {
		i++
	}
	if i < len(p) && p[i] == ']' {
		i++
	}
	for i < len(p) && p[i] != ']' {
		i++
	}
	if i == len(p) {
		return 0
	}
	return i + 1
}

// matchClass reports whether c belongs to the class in p (including [!...] /
// [^...] negation and a-z ranges).
func matchClass(p string, c byte) bool {
	inner := p[1 : len(p)-1]
	negate := false
	if strings.HasPrefix(inner, "^") || strings.HasPrefix(inner, "!") {
		negate = true
		inner = inner[1:]
	}
	matched := false
	for i := 0; i < len(inner); i++ {
		if i+2 < len(inner) && inner[i+1] == '-' {
			if inner[i] <= c && c <= inner[i+2] {
				matched = true
			}
			i += 2
			continue
		}
		if inner[i] == c {
			matched = true
		}
	}
	if negate {
		return !matched
	}
	return matched
}

// MatchesAny reports whether argv satisfies any of the specs.
func MatchesAny(specs []CommandSpec, argv []string) bool {
	for _, s := range specs {
		if s.MatchesArgv(argv) {
			return true
		}
	}
	return false
}

// dumpers are executables that read environment, files, or streams and write
// them to stdout — the lazy path a prompt-injected command would take. Matched
// by basename, so /usr/bin/env and a differently-pathed equivalent are both
// caught.
var dumpers = map[string]bool{
	"env": true, "printenv": true, "set": true, "export": true,
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"echo": true, "printf": true, "tee": true,
	"cp": true, "mv": true, "dd": true,
	"base64": true, "xxd": true, "od": true, "hexdump": true, "strings": true,
}

// interpretersWithInlineCode map interpreters to the flags that make them
// execute inline code — the vector by which `python3 -c 'import
// os;print(os.environ[...])'` becomes an arbitrary-value printer. A shell or
// interpreter WITHOUT an inline-code flag is not refused here: running
// `/usr/bin/python3 script.py` is a legitimate consumer shape.
var interpretersWithInlineCode = map[string][]string{
	"sh": {"-c"}, "bash": {"-c"}, "zsh": {"-c"}, "fish": {"-c"},
	"python": {"-c"}, "python3": {"-c"},
	"node":      {"-e", "--eval"},
	"perl":      {"-e"},
	"ruby":      {"-e"},
	"php":       {"-r"},
	"awk":       {""}, // awk takes a program string positionally: awk 'BEGIN{...}'
	"gawk":      {""},
	"osascript": {"-e"},
}

// Refuses reports whether the backstop denylist refuses this argv. A nil or
// empty argv refuses nothing (there is no command to judge; the injection
// method handles that case).
func Refuses(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	base := basename(argv[0])

	if dumpers[base] {
		return true
	}
	if flags, ok := interpretersWithInlineCode[base]; ok {
		return interpreterRefused(argv, flags)
	}
	return false
}

// interpreterRefused decides for an interpreter: refused when it carries an
// inline-code flag, or (for awk) when invoked with a positional program that
// references the injected environment is out of scope here — a positional awk
// program IS inline code, so any bare awk invocation with arguments beyond
// flags and a program string is refused. Simpler and honest: awk without -f
// is inline code by construction.
func interpreterRefused(argv []string, inlineFlags []string) bool {
	if len(inlineFlags) == 1 && inlineFlags[0] == "" {
		// Positional-program interpreter (awk family). Inline code unless -f
		// names a program file.
		for _, a := range argv[1:] {
			if a == "-f" || strings.HasPrefix(a, "-f") {
				return false
			}
		}
		return len(argv) > 1
	}
	for _, a := range argv[1:] {
		for _, f := range inlineFlags {
			if a == f || strings.HasPrefix(a, f+"=") || (len(f) > 1 && strings.HasPrefix(a, f)) {
				return true
			}
		}
	}
	return false
}

// basename returns the final path element of s.
func basename(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}
