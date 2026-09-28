// Package redact scans captured command output for the resolved secret
// value — and substrings of it — before the sidecar relays that output to
// any caller.
//
// Governing spec: .usm/features/resolution/output-control.usm, contract
// output-redacted-in-sidecar. The point of the package is that a
// prompt-injected command cannot echo the injected value back to the model
// through the relay channel: raw, base64, base64url, hex, percent-encoded,
// and JSON-escaped renderings are all matched, including renderings split
// across line or chunk boundaries, and substrings of the value of 8+
// characters (or the whole value when it is shorter).
//
// Matches are replaced with [REDACTED:safekeys]. The package reports HOW
// MANY matches occurred and in which encoding classes, never the values.
//
// This is defence in depth on one channel. It does not make an arbitrary
// allowed command safe — a command can exfiltrate over the network or write
// the value to a file. The allowlist is the control for that; this package
// only closes the relay.
package redact

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// Placeholder replaces every matched rendering of the secret.
const Placeholder = "[REDACTED:safekeys]"

// minSubstringLen is the shortest secret substring treated as a match. Below
// this, partial echoes are not redacted: short fragments would fire on
// ordinary output and destroy the utility of relaying anything at all. An
// 8-character floor is a deliberate trade of completeness for practicality,
// recorded in the spec's substrings-not-whole-value decision.
const minSubstringLen = 8

// Report summarises what a scan did. It carries counts and encoding classes
// only — never the value or any fragment of it — so it can go to the audit
// log unchanged.
type Report struct {
	Matches   int
	Encodings []string // e.g. ["raw","base64"]; de-duplicated, sorted
}

// Redacted reports whether anything was replaced.
func (r Report) Redacted() bool { return r.Matches > 0 }

// Scanner holds the match set for one resolved value and is reused across
// the stdout and stderr of a single resolve. Build one per resolve with
// New; a Scanner is not safe for concurrent use, which is fine — one
// resolve owns its output.
type Scanner struct {
	// needles are literal byte sequences to find: the raw value, each
	// encoded form, and the encoded/raw substrings of 8+ characters.
	needles []needle
	// jsonEscaped is the JSON-escaped rendering of the full value; JSON
	// escaping is length-dependent (\" inserts, \n becomes \\n), so it is
	// handled with a dedicated matcher rather than a fixed needle.
	jsonEscaped string
	// rawJSONEscapable records whether the raw value itself can appear
	// verbatim inside a JSON string (no quotes/backslashes/control chars),
	// in which case the raw needle already covers JSON contexts.
	rawJSONEscapable bool
	// valueLen is the original value length in bytes.
	valueLen int
}

type needle struct {
	b        []byte
	encoding string // reporting label
}

// New builds a scanner for one resolved value.
//
// Substring handling: every substring of the value of minSubstringLen or
// more bytes is registered in raw and encoded form. A value shorter than
// minSubstringLen is matched only in full — redacting 3-character fragments
// would corrupt unrelated output.
func New(value []byte) *Scanner {
	s := &Scanner{valueLen: len(value)}
	if len(value) == 0 {
		return s
	}

	add := func(b []byte, enc string) {
		if len(b) == 0 {
			return
		}
		s.needles = append(s.needles, needle{b: append([]byte(nil), b...), encoding: enc})
	}

	// Raw value and its substrings.
	substrings(value, func(sub []byte) {
		add(sub, "raw")
	})

	// Encoded forms of the full value...
	rawB64 := base64.StdEncoding.EncodeToString(value)
	rawB64URL := base64.URLEncoding.EncodeToString(value)
	rawB64RawURL := base64.RawURLEncoding.EncodeToString(value)
	rawHex := hex.EncodeToString(value)
	rawPct := percentEncode(value)

	add([]byte(rawB64), "base64")
	add([]byte(rawB64URL), "base64url")
	add([]byte(rawB64RawURL), "base64url") // unpadded URL variant
	add([]byte(rawHex), "hex")
	add([]byte(rawHex), "hex") // uppercase variant added below
	add([]byte(strings.ToUpper(rawHex)), "hex")
	add([]byte(rawPct), "percent")

	// ...and of each substring, because a partial echo survives base64
	// differently than raw: base64("secretval") shares no literal bytes
	// with base64("secretvalfoo"), so the full-value encoding alone would
	// miss a sliced echo. Encoding every substring covers it.
	substrings(value, func(sub []byte) {
		add([]byte(base64.StdEncoding.EncodeToString(sub)), "base64")
		add([]byte(base64.URLEncoding.EncodeToString(sub)), "base64url")
		add([]byte(base64.RawURLEncoding.EncodeToString(sub)), "base64url")
		add([]byte(hex.EncodeToString(sub)), "hex")
		add([]byte(strings.ToUpper(hex.EncodeToString(sub))), "hex")
		add([]byte(percentEncode(sub)), "percent")
	})

	// JSON escaping of the full value. If the value is plain (letters,
	// digits, safe punctuation), a JSON string containing it looks
	// identical to the raw bytes and the raw needle already matches; the
	// dedicated needle only matters when escaping changes the bytes.
	s.rawJSONEscapable = jsonVerbatim(value)
	s.jsonEscaped = jsonEscape(value)
	if !s.rawJSONEscapable {
		add([]byte(s.jsonEscaped), "json")
		// Substrings too — but only those that need escaping, else raw
		// already covers them.
		substrings(value, func(sub []byte) {
			if !jsonVerbatim(sub) {
				add([]byte(jsonEscape(sub)), "json")
			}
		})
	}

	return s
}

// substrings calls fn for every contiguous substring of v with length
// >= minSubstringLen, longest first. For a value shorter than
// minSubstringLen it calls fn once with the whole value.
func substrings(v []byte, fn func([]byte)) {
	if len(v) == 0 {
		return
	}
	if len(v) < minSubstringLen {
		fn(v)
		return
	}
	// Longest first so the scan replaces the largest match available; a
	// shorter needle inside a longer one is redundant work avoided by
	// scanning order, not by deduplication.
	for l := len(v); l >= minSubstringLen; l-- {
		for i := 0; i+l <= len(v); i++ {
			fn(v[i : i+l])
		}
	}
}

// Scan replaces every occurrence of the value — in any supported rendering,
// including split across boundaries — with Placeholder. It returns the
// rewritten output and a report safe for the audit log.
//
// Split handling: encodings of a multi-byte value can be wrapped across
// lines (base64 -w, log rotation, chunked writes). After literal matching,
// the input is normalised — CRLF→LF, whitespace runs collapsed — and
// re-scanned; if the normalised form matches where the raw form did not,
// the affected region is redacted in the ORIGINAL output by replacing the
// bytes that produced the match.
func (s *Scanner) Scan(out []byte) ([]byte, Report) {
	rep := Report{}
	if len(out) == 0 || len(s.needles) == 0 {
		return out, rep
	}

	out, n := s.scanLiteral(out, &rep)
	if n > 0 {
		// Literal pass found something; still run the split pass in case
		// more remains wrapped.
	}
	n2 := s.scanSplit(out, &rep)
	rep.Matches += n2
	return out, rep
}

// scanLiteral does the direct substring passes and rewrites out in place.
func (s *Scanner) scanLiteral(out []byte, rep *Report) ([]byte, int) {
	total := 0
	for _, nd := range s.needles {
		for {
			idx := indexBytes(out, nd.b)
			if idx < 0 {
				break
			}
			out = replaceRange(out, idx, idx+len(nd.b), []byte(Placeholder))
			rep.Matches++
			total++
			rep.note(nd.encoding)
		}
	}
	// JSON-escaped full value, when the raw needle cannot cover it.
	if s.jsonEscaped != "" && !s.rawJSONEscapable {
		j := []byte(s.jsonEscaped)
		for {
			idx := indexBytes(out, j)
			if idx < 0 {
				break
			}
			out = replaceRange(out, idx, idx+len(j), []byte(Placeholder))
			rep.Matches++
			total++
			rep.note("json")
		}
	}
	return out, total
}

// scanSplit catches renderings broken across line breaks, whitespace, or
// chunk boundaries — e.g. base64 with folded wrapping, or a value written in
// two write() calls separated by a newline. It builds a whitespace-elided
// view of the output, scans THAT, and maps any match back onto the original
// byte span so the original is redacted. Whitespace between two halves of an
// encoded value is an artefact of wrapping, not part of the value.
func (s *Scanner) scanSplit(out []byte, rep *Report) int {
	// Elide whitespace: norm holds the remaining bytes, origs[i] the index
	// in out that norm[i] came from.
	norm, origs := elide(out)

	total := 0
	for _, nd := range s.needles {
		if len(nd.b) < 8 {
			continue // split detection is pointless for tiny needles
		}
		for {
			idx := indexBytes(norm, nd.b)
			if idx < 0 {
				break
			}
			// Map [idx, idx+len) back to the original span. The span runs
			// from the first matched byte through the last matched byte,
			// INCLUDING any elided whitespace between them — those bytes
			// were part of the folded rendering.
			start := origs[idx]
			endIdx := idx + len(nd.b) - 1
			end := len(out)
			if endIdx+1 < len(origs) {
				end = origs[endIdx+1] // first original byte after the match
			}
			out = replaceRange(out, start, end, []byte(Placeholder))
			norm, origs = elide(out)
			rep.Matches++
			total++
			rep.note(nd.encoding)
		}
	}
	return total
}

// elide removes CR, LF, TAB, and space from out, returning the compacted
// bytes and, for each kept byte, its original index.
func elide(out []byte) ([]byte, []int) {
	norm := make([]byte, 0, len(out))
	origs := make([]int, 0, len(out))
	for i, c := range out {
		if c == '\r' || c == '\n' || c == '\t' || c == ' ' {
			continue
		}
		norm = append(norm, c)
		origs = append(origs, i)
	}
	return norm, origs
}

// note records an encoding class in the report, deduplicated.
func (r *Report) note(enc string) {
	for _, e := range r.Encodings {
		if e == enc {
			return
		}
	}
	r.Encodings = append(r.Encodings, enc)
}

// indexBytes is bytes.Index.
func indexBytes(haystack, needle []byte) int { return strings.Index(string(haystack), string(needle)) }

// replaceRange replaces out[a:b] with repl, allocating once.
func replaceRange(out []byte, a, b int, repl []byte) []byte {
	res := make([]byte, 0, len(out)-b+len(repl))
	res = append(res, out[:a]...)
	res = append(res, repl...)
	res = append(res, out[b:]...)
	return res
}

// percentEncode renders v the way encodeURIComponent/url.QueryEscape would:
// every byte outside the unreserved set becomes %XX, uppercase hex.
func percentEncode(v []byte) string {
	var b strings.Builder
	for _, c := range v {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		const hexdig = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hexdig[c>>4])
		b.WriteByte(hexdig[c&0xf])
	}
	return b.String()
}

// jsonEscape renders v as the bytes that would appear INSIDE a JSON string
// literal (without the surrounding quotes) under Go's encoding/json rules —
// the escaping most JSON serializers produce for these bytes.
func jsonEscape(v []byte) string {
	var b strings.Builder
	for _, c := range v {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 {
				const hexdig = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hexdig[c>>4])
				b.WriteByte(hexdig[c&0xf])
				continue
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

// jsonVerbatim reports whether v can appear unchanged inside a JSON string.
func jsonVerbatim(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}
