package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// The canary: a value with letters, digits, and punctuation — realistic
// secret material, and hard enough to exercise every encoding path.
const canary = "sk-live-Qx7#mVt2$wZn8pLr"

func mustScan(t *testing.T, s *Scanner, out string) (string, Report) {
	t.Helper()
	got, rep := s.Scan([]byte(out))
	return string(got), rep
}

func assertNoLeak(t *testing.T, got, stage string) {
	t.Helper()
	if strings.Contains(got, canary) {
		t.Fatalf("%s: raw value leaked: %q", stage, got)
	}
	for _, enc := range encodedRenderings(canary) {
		if strings.Contains(got, enc) {
			t.Fatalf("%s: encoded form leaked (%s...): %q", stage, enc[:12], got)
		}
	}
}

// encodedRenderings produces every encoding the scanner is expected to catch,
// used to assert none of them survive.
func encodedRenderings(v string) []string {
	b := []byte(v)
	out := []string{
		base64.StdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		url.QueryEscape(v),
	}
	return out
}

func TestFullValueRawRedacted(t *testing.T) {
	s := New([]byte(canary))
	got, rep := mustScan(t, s, "token="+canary+"\n")
	assertNoLeak(t, got, "raw")
	if !strings.Contains(got, Placeholder) {
		t.Fatalf("placeholder missing: %q", got)
	}
	if !rep.Redacted() || rep.Matches != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Encodings) != 1 || rep.Encodings[0] != "raw" {
		t.Fatalf("encodings = %v", rep.Encodings)
	}
}

func TestEncodedFormsRedacted(t *testing.T) {
	cases := []struct {
		name string
		f    func(string) string
	}{
		{"base64", func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }},
		{"base64url", func(v string) string { return base64.URLEncoding.EncodeToString([]byte(v)) }},
		{"base64-rawurl", func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }},
		{"hex-lower", func(v string) string { return hex.EncodeToString([]byte(v)) }},
		{"hex-upper", func(v string) string { return strings.ToUpper(hex.EncodeToString([]byte(v))) }},
		{"percent", func(v string) string { return url.QueryEscape(v) }},
		{"json-escaped", func(v string) string {
			// The canary contains #, $, # — JSON-safe, but use a value
			// with a quote to force real escaping.
			return `{"k":"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"}`
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// A quote-bearing value exercises the JSON path meaningfully.
			val := `p@ss"w0rd\int/seq`
			s := New([]byte(val))
			out := tc.f(val)
			got, rep := mustScan(t, s, "data: "+out)
			if strings.Contains(got, out) {
				t.Fatalf("encoded form survived: %q", got)
			}
			if !rep.Redacted() {
				t.Fatal("no redaction reported")
			}
		})
	}
}

func TestPartialLeakRedacted(t *testing.T) {
	// cut -c1-20 style: a prefix echo.
	s := New([]byte(canary))
	prefix := canary[:20]
	got, _ := mustScan(t, s, "first 20: "+prefix)
	if strings.Contains(got, prefix) {
		t.Fatalf("20-char prefix survived: %q", got)
	}
	if !strings.Contains(got, Placeholder) {
		t.Fatalf("placeholder missing: %q", got)
	}

	// A suffix echo too.
	suffix := canary[len(canary)-9:]
	got, _ = mustScan(t, s, "tail: "+suffix)
	if strings.Contains(got, suffix) {
		t.Fatalf("9-char suffix survived: %q", got)
	}

	// A middle slice.
	mid := canary[5:14]
	got, _ = mustScan(t, s, "mid: "+mid)
	if strings.Contains(got, mid) {
		t.Fatalf("9-char middle slice survived: %q", got)
	}
}

func TestShortFragmentsNotRedacted(t *testing.T) {
	// Substrings below 8 characters must NOT be treated as matches, or
	// ordinary output containing e.g. "sk" would be corrupted.
	s := New([]byte(canary))
	got, rep := mustScan(t, s, "fragment: "+canary[:7]+" — and the word safekeys elsewhere")
	if rep.Redacted() {
		t.Fatalf("7-char fragment redacted: %q", got)
	}
}

func TestShortValueMatchedInFull(t *testing.T) {
	// A 7-char value has no eligible substrings, but the full value must
	// still be caught in raw form.
	short := "abc-123"
	s := New([]byte(short))
	got, rep := mustScan(t, s, "v="+short)
	if strings.Contains(got, short) {
		t.Fatalf("short value survived: %q", got)
	}
	if !rep.Redacted() {
		t.Fatal("no redaction reported")
	}
}

func TestBase64WrappedAcrossLinesRedacted(t *testing.T) {
	// base64 -w16 style folding: the encoded value is broken with newlines.
	s := New([]byte(canary))
	enc := base64.StdEncoding.EncodeToString([]byte(canary))
	wrapped := fold(enc, 16)
	got, rep := mustScan(t, s, wrapped)
	if !rep.Redacted() {
		t.Fatalf("wrapped base64 not detected: %q", got)
	}
	if strings.Contains(got, enc) {
		t.Fatal("unwrapped encoding still present")
	}
}

func fold(s string, width int) string {
	var parts []string
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, "\n")
}

func TestSplitAcrossStdoutAndStderrRedacted(t *testing.T) {
	// Half the value in one stream, half in the other; the sidecar scans
	// the concatenation, so model the combined buffer here.
	s := New([]byte(canary))
	half := len(canary) / 2
	combined := canary[:half] + "\n" + canary[half:]
	got, rep := mustScan(t, s, combined)
	if !rep.Redacted() {
		t.Fatalf("split value not detected: %q", got)
	}
	if strings.Contains(got, canary) {
		t.Fatalf("recombined value survived: %q", got)
	}
}

func TestSplitAcrossChunksRedacted(t *testing.T) {
	// The value written in two chunks with intervening output — the
	// scanner sees the whole buffer, so any interleaving that leaves the
	// bytes contiguous is caught. Verify via the raw needle.
	s := New([]byte(canary))
	noise := "status: ok\n"
	got, _ := mustScan(t, s, noise+canary+noise)
	if strings.Contains(got, canary) {
		t.Fatal("contiguous split chunks survived")
	}
}

func TestJSONContextEscaped(t *testing.T) {
	// A value with characters JSON must escape, printed by a command that
	// serialises its environment.
	val := `tok"en\val`
	s := New([]byte(val))
	out := fmt.Sprintf(`{"env":{"T":"%s"}}`, strings.ReplaceAll(strings.ReplaceAll(val, `\`, `\\`), `"`, `\"`))
	got, rep := mustScan(t, s, out)
	if strings.Contains(got, val) || strings.Contains(got, `tok\"en\\val`) {
		t.Fatalf("json-escaped value survived: %q", got)
	}
	if !rep.Redacted() {
		t.Fatal("no redaction reported")
	}
}

func TestPlainValueCoveredByRawNeedleInJSON(t *testing.T) {
	// A JSON-safe value inside a JSON string is caught by the raw needle.
	s := New([]byte(canary))
	out := fmt.Sprintf(`{"token":"%s"}`, canary)
	got, _ := mustScan(t, s, out)
	if strings.Contains(got, canary) {
		t.Fatalf("value in JSON survived: %q", got)
	}
}

func TestPercentEncodedSplit(t *testing.T) {
	// percent-encoding of a value with a special char, then wrapped.
	val := "abc=def+ghi"
	s := New([]byte(val))
	enc := url.QueryEscape(val)
	wrapped := fold(enc, 5)
	got, rep := mustScan(t, s, wrapped)
	if !rep.Redacted() {
		t.Fatalf("wrapped percent-encoding not detected: %q", got)
	}
	if strings.Contains(got, enc) {
		t.Fatal("encoding still present")
	}
}

func TestEmptyScannerNoop(t *testing.T) {
	s := New(nil)
	got, rep := mustScan(t, s, "nothing to see here")
	if got != "nothing to see here" || rep.Redacted() {
		t.Fatalf("empty scanner mutated output: %q %+v", got, rep)
	}
}

func TestReportCarriesNoValueMaterial(t *testing.T) {
	// Structural: the Report type has no fields capable of holding the
	// value. Compile-time shape plus a runtime sanity check.
	s := New([]byte(canary))
	_, rep := mustScan(t, s, canary)
	blob := fmt.Sprintf("%+v", rep)
	if strings.Contains(blob, canary) {
		t.Fatal("report contains value material")
	}
}

func TestSubstringsLongestFirst(t *testing.T) {
	// A value where a long substring appears; the whole value is replaced
	// (longest needle wins by scan order), leaving no residue.
	s := New([]byte(canary))
	out := canary + " and " + canary[:9]
	got, rep := mustScan(t, s, out)
	assertNoLeak(t, got, "multi")
	if rep.Matches < 2 {
		t.Fatalf("expected >=2 matches, got %d", rep.Matches)
	}
}

func TestMultipleOccurrences(t *testing.T) {
	s := New([]byte(canary))
	out := strings.Repeat(canary+"\n", 3)
	got, rep := mustScan(t, s, out)
	assertNoLeak(t, got, "repeat")
	if rep.Matches < 3 {
		t.Fatalf("expected >=3 matches, got %d", rep.Matches)
	}
}

func TestLargeOutputNotDegenerate(t *testing.T) {
	// The scanner must not blow up on large output with many needles
	// (substring enumeration is O(n^2) needles — bound the practical cost
	// by verifying a 1 MiB buffer completes quickly enough for a test).
	s := New([]byte(canary))
	big := bytes.Repeat([]byte("x"), 1<<20)
	big = append(big, []byte(canary)...)
	got, rep := mustScan(t, s, string(big))
	if !rep.Redacted() {
		t.Fatal("needle in 1MiB buffer missed")
	}
	if strings.Contains(got, canary) {
		t.Fatal("value survived in large buffer")
	}
}
