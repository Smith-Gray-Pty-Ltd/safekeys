package protocol

import "errors"

// Denial is the error returned when a token or request is refused.
//
// Resolve responses are deliberately generic — see ADR generic-denials. A
// caller learns only that it was denied; the machine-readable Reason is
// recorded in the audit log and never returned over the wire, because a
// detailed reason is a probing oracle for an attacker refining a forged token.
type Denial struct {
	// Reason is the machine-readable cause. Audit-only: never serialise this
	// into a client-visible response.
	Reason string
}

func (d *Denial) Error() string { return "denied" }

// NewDenial builds a denial with the given audit-only reason.
func NewDenial(reason string) error { return &Denial{Reason: reason} }

// Denial reasons. These mirror the conformance vector expectations in
// spec/capability-token/v1.vectors.json and are recorded verbatim in audit.
const (
	ReasonMalformed           = "malformed"
	ReasonSignatureInvalid    = "signature_invalid"
	ReasonAlgNotAllowed       = "alg_not_allowed"
	ReasonKidMissing          = "kid_missing"
	ReasonKidUnknown          = "kid_unknown"
	ReasonExpired             = "exp"
	ReasonNotYetValid         = "nbf"
	ReasonAudienceMismatch    = "aud"
	ReasonScopeNotGranted     = "scope"
	ReasonRevoked             = "revoked"
	ReasonSIDPathMismatch     = "sid_path_mismatch"
	ReasonUnsupportedVersion  = "unsupported_version"
	ReasonPolicyDenied        = "policy_denied"
	ReasonKeystoreUnreachable = "keystore_unreachable"
	ReasonNoResolver          = "no_resolver"
)

// ReasonOf extracts the audit reason from err, or "" if it is not a Denial.
func ReasonOf(err error) string {
	var d *Denial
	if errors.As(err, &d) {
		return d.Reason
	}
	return ""
}
