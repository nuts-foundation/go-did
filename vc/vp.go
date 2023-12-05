package vc

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"strings"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/internal/marshal"
)

// VerifiablePresentationType is the default credential type required for every credential
const VerifiablePresentationType = "VerifiablePresentation"

// VerifiablePresentationTypeV1URI returns VerifiablePresentation as URI
func VerifiablePresentationTypeV1URI() ssi.URI {
	return ssi.MustParseURI(VerifiablePresentationType)
}

const (
	// JSONLDPresentationProofFormat is the format for JSON-LD based presentations.
	JSONLDPresentationProofFormat string = "ldp_vp"
	// JWTPresentationProofFormat is the format for JWT based presentations.
	// Note: various specs have not yet decided on the exact const (jwt_vp or jwt_vp_json, etc), so this is subject to change.
	JWTPresentationProofFormat = "jwt_vp"
)

// VerifiablePresentation represents a presentation as defined by the Verifiable Credentials Data Model 1.0 specification (https://www.w3.org/TR/vc-data-model/).
type VerifiablePresentation struct {
	// Context defines the json-ld context to dereference the URIs
	Context []ssi.URI `json:"@context"`
	// ID is an unique identifier for the presentation. It is optional
	ID *ssi.URI `json:"id,omitempty"`
	// Type holds multiple types for a presentation. A presentation must always have the 'VerifiablePresentation' type.
	Type []ssi.URI `json:"type"`
	// Holder refers to the party that generated the presentation. It is optional
	Holder *ssi.URI `json:"holder,omitempty"`
	// VerifiableCredential may hold credentials that are proven with this presentation.
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty"`
	// Proof contains the cryptographic proof(s). It must be extracted using the Proofs method or UnmarshalProofValue method for non-generic proof fields.
	Proof []interface{} `json:"proof,omitempty"`

	format string
	raw    string
	token  jwt.Token
}

// ParseVerifiablePresentation parses a Verifiable Presentation from a string, which can be either in JSON-LD or JWT format.
// If the format is JWT, the parsed token can be retrieved using JWT().
// Note that it does not do any signature checking, or check that the signer of the VP is the subject of the VCs.
func ParseVerifiablePresentation(raw string) (*VerifiablePresentation, error) {
	if strings.HasPrefix(raw, "{") {
		// Assume JSON-LD format
		return parseJSONLDPresentation(raw)
	} else {
		// Assume JWT format
		return parseJTWPresentation(raw)
	}
}

func parseJSONLDPresentation(raw string) (*VerifiablePresentation, error) {
	type Alias VerifiablePresentation
	normalizedVC, err := marshal.NormalizeDocument([]byte(raw), pluralContext, marshal.Plural(typeKey), marshal.Plural(verifiableCredentialKey), marshal.Plural(proofKey))
	if err != nil {
		return nil, err
	}
	alias := Alias{}
	err = json.Unmarshal(normalizedVC, &alias)
	if err != nil {
		return nil, err
	}
	alias.raw = raw
	alias.format = JSONLDPresentationProofFormat
	result := VerifiablePresentation(alias)
	return &result, err
}

func parseJTWPresentation(raw string) (*VerifiablePresentation, error) {
	token, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, err
	}
	var result VerifiablePresentation
	if innerVPInterf := token.PrivateClaims()["vp"]; innerVPInterf != nil {
		innerVPJSON, _ := json.Marshal(innerVPInterf)
		err = json.Unmarshal(innerVPJSON, &result)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT 'vp' claim: %w", err)
		}
	}
	// parse jti
	if jti, err := parseURIClaim(token, jwt.JwtIDKey); err != nil {
		return nil, err
	} else if jti != nil {
		result.ID = jti
	}
	// parse iss
	if iss, err := parseURIClaim(token, jwt.IssuerKey); err != nil {
		return nil, err
	} else if iss != nil {
		result.Holder = iss
	}
	// the other claims don't have a designated field in VerifiablePresentation and can be accessed through JWT()
	result.format = JWTPresentationProofFormat
	result.raw = raw
	result.token = token
	return &result, nil
}

func parseURIClaim(token jwt.Token, claim string) (*ssi.URI, error) {
	if val, ok := token.Get(claim); ok {
		if str, ok := val.(string); !ok {
			return nil, fmt.Errorf("%s must be a string", claim)
		} else {
			return ssi.ParseURI(str)
		}
	}
	return nil, nil
}

// Format returns the format of the presentation (e.g. jwt_vp or ldp_vp).
func (vp VerifiablePresentation) Format() string {
	return vp.format
}

// JWT returns the JWT token if the presentation was parsed from a JWT.
func (vp VerifiablePresentation) JWT() jwt.Token {
	if vp.token == nil {
		return nil
	}
	token, _ := vp.token.Clone()
	return token
}

// Raw returns the source of the presentation as it was parsed.
func (vp VerifiablePresentation) Raw() string {
	return vp.raw
}

// Proofs returns the basic proofs for this presentation. For specific proof contents, UnmarshalProofValue must be used.
func (vp VerifiablePresentation) Proofs() ([]Proof, error) {
	var (
		target []Proof
		err    error
		asJSON []byte
	)
	asJSON, err = json.Marshal(vp.Proof)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(asJSON, &target)
	return target, err
}

func (vp VerifiablePresentation) MarshalJSON() ([]byte, error) {
	if vp.raw != "" {
		// Presentation instance created through ParseVerifiablePresentation()
		if vp.format == JWTPresentationProofFormat {
			// Marshal as JSON string
			return json.Marshal(vp.raw)
		}
		// JSON-LD, already in JSON format so return as-is
		return []byte(vp.raw), nil
	}
	type alias VerifiablePresentation
	tmp := alias(vp)
	if data, err := json.Marshal(tmp); err != nil {
		return nil, err
	} else {
		return marshal.NormalizeDocument(data, pluralContext, marshal.Unplural(typeKey), marshal.Unplural(verifiableCredentialKey), marshal.Unplural(proofKey))
	}
}

func (vp *VerifiablePresentation) UnmarshalJSON(b []byte) error {
	var str string
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
	} else {
		str = string(b)
	}
	presentation, err := ParseVerifiablePresentation(str)
	if err == nil {
		*vp = *presentation
	}
	return err
}

// UnmarshalProofValue unmarshalls the proof to the given proof type. Always pass a slice as target since there could be multiple proofs.
// Each proof will result in a value, where null values may exist when the proof doesn't have the json member.
func (vp VerifiablePresentation) UnmarshalProofValue(target interface{}) error {
	if asJSON, err := json.Marshal(vp.Proof); err != nil {
		return err
	} else {
		return json.Unmarshal(asJSON, target)
	}
}

// IsType returns true when a presentation contains the requested type
func (vp VerifiablePresentation) IsType(vcType ssi.URI) bool {
	for _, t := range vp.Type {
		if t.String() == vcType.String() {
			return true
		}
	}

	return false
}

// ContainsContext returns true when a credential contains the requested context
func (vp VerifiablePresentation) ContainsContext(context ssi.URI) bool {
	for _, c := range vp.Context {
		if c.String() == context.String() {
			return true
		}
	}

	return false
}
