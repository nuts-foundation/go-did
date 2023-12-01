package vc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"

	"github.com/nuts-foundation/go-did/internal/marshal"
)

// VerifiableCredentialType is the default credential type required for every credential
const VerifiableCredentialType = "VerifiableCredential"

// VerifiableCredentialTypeV1URI returns VerifiableCredential as URI
func VerifiableCredentialTypeV1URI() ssi.URI {
	return ssi.MustParseURI(VerifiableCredentialType)
}

// VCContextV1 is the context required for every credential and presentation
const VCContextV1 = "https://www.w3.org/2018/credentials/v1"

// VCContextV1URI returns 'https://www.w3.org/2018/credentials/v1' as URI
func VCContextV1URI() ssi.URI {
	if pURI, err := ssi.ParseURI(VCContextV1); err != nil {
		panic(err)
	} else {
		return *pURI
	}
}

const (
	// JSONLDCredentialProofFormat is the format for JSON-LD based credentials.
	JSONLDCredentialProofFormat string = "ldp_vc"
	// JWTCredentialProofFormat is the format for JWT based credentials.
	// Note: various specs have not yet decided on the exact const (jwt_vc or jwt_vc_json, etc), so this is subject to change.
	JWTCredentialProofFormat = "jwt_vc"
)

var errCredentialSubjectWithoutID = errors.New("credential subjects have no ID")

// ParseVerifiableCredential parses a Verifiable Credential from a string, which can be either in JSON-LD or JWT format.
// JWTs are parsed according to https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#jwt-decoding
// If the format is JWT, the parsed token can be retrieved using JWT().
// Note that it does not do any signature checking.
func ParseVerifiableCredential(raw string) (*VerifiableCredential, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		// Assume JSON-LD format
		return parseJSONLDCredential(raw)
	} else {
		// Assume JWT format
		return parseJWTCredential(raw)
	}
}

// parseJWTCredential parses a JWT credential according to https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#jwt-decoding
func parseJWTCredential(raw string) (*VerifiableCredential, error) {
	token, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, err
	}
	var result VerifiableCredential
	if innerVCInterf := token.PrivateClaims()["vc"]; innerVCInterf != nil {
		innerVCJSON, _ := json.Marshal(innerVCInterf)
		err = json.Unmarshal(innerVCJSON, &result)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT 'vc' claim: %w", err)
		}
	}
	// parse exp
	if _, ok := token.Get(jwt.ExpirationKey); ok {
		exp := token.Expiration()
		result.ExpirationDate = &exp
	}
	// parse iss
	if iss, err := parseURIClaim(token, jwt.IssuerKey); err != nil {
		return nil, err
	} else if iss != nil {
		result.Issuer = *iss
	}
	// parse nbf
	if _, ok := token.Get(jwt.NotBeforeKey); ok {
		nbf := token.NotBefore()
		result.IssuanceDate = &nbf
	}
	// parse sub
	if token.Subject() != "" {
		for _, credentialSubjectInterf := range result.CredentialSubject {
			credentialSubject, isMap := credentialSubjectInterf.(map[string]interface{})
			if isMap {
				credentialSubject["id"] = token.Subject()
			}
		}
	}
	// parse jti
	if jti, err := parseURIClaim(token, jwt.JwtIDKey); err != nil {
		return nil, err
	} else if jti != nil {
		result.ID = jti
	}
	result.format = JWTCredentialProofFormat
	result.raw = raw
	result.token = token
	return &result, nil
}

func parseJSONLDCredential(raw string) (*VerifiableCredential, error) {
	type Alias VerifiableCredential
	normalizedVC, err := marshal.NormalizeDocument([]byte(raw), pluralContext, marshal.Plural(typeKey), marshal.Plural(credentialSubjectKey), marshal.Plural(credentialStatusKey), marshal.Plural(proofKey))
	if err != nil {
		return nil, err
	}
	alias := Alias{}
	err = json.Unmarshal(normalizedVC, &alias)
	if err != nil {
		return nil, err
	}
	alias.format = JSONLDCredentialProofFormat
	alias.raw = raw
	result := VerifiableCredential(alias)
	return &result, err
}

// VerifiableCredential represents a credential as defined by the Verifiable Credentials Data Model 1.0 specification (https://www.w3.org/TR/vc-data-model/).
type VerifiableCredential struct {
	// Context defines the json-ld context to dereference the URIs
	Context []ssi.URI `json:"@context"`
	// ID is an unique identifier for the credential. It is optional
	ID *ssi.URI `json:"id,omitempty"`
	// Type holds multiple types for a credential. A credential must always have the 'VerifiableCredential' type.
	Type []ssi.URI `json:"type"`
	// Issuer refers to the party that issued the credential
	Issuer ssi.URI `json:"issuer"`
	// IssuanceDate is a rfc3339 formatted datetime. It is required, but may be replaced by alias ValidFrom
	IssuanceDate *time.Time `json:"issuanceDate,omitempty"`
	// ValidFrom is a rfc3339 formatted datetime. It is optional, and is mutually exclusive with IssuanceDate (not enforced).
	// It's a forwards compatible (vc data model v2) alternative for IssuanceDate.
	// The jwt-vc 'nbf' field will unmarshal to IssuanceDate, which may not match with the JSON-LD definition of certain VCs.
	ValidFrom *time.Time `json:"validFrom,omitempty"`
	// ExpirationDate is a rfc3339 formatted datetime. Has alias ValidUntil. It is optional
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
	// ValidFrom is a rfc3339 formatted datetime. It is optional, and is mutually exclusive with ExpirationDate (not enforced).
	// It's a forwards compatible (vc data model v2) alternative for ExpirationDate.
	// The jwt-vc 'exp' field will unmarshal to ExpirationDate, which may not match with the JSON-LD definition of certain VCs.
	ValidUntil *time.Time `json:"validUntil,omitempty"`
	// CredentialStatus holds information on how the credential can be revoked. It must be extracted using the UnmarshalCredentialStatus method and a custom type.
	CredentialStatus []any `json:"credentialStatus,omitempty"`
	// CredentialSubject holds the actual data for the credential. It must be extracted using the UnmarshalCredentialSubject method and a custom type.
	CredentialSubject []interface{} `json:"credentialSubject"`
	// Proof contains the cryptographic proof(s). It must be extracted using the Proofs method or UnmarshalProofValue method for non-generic proof fields.
	Proof []interface{} `json:"proof"`

	format string
	raw    string
	token  jwt.Token
}

// Format returns the format of the credential (e.g. jwt_vc or ldp_vc).
func (vc VerifiableCredential) Format() string {
	return vc.format
}

// Raw returns the source of the credential as it was parsed.
func (vc VerifiableCredential) Raw() string {
	return vc.raw
}

// JWT returns the JWT token if the credential was parsed from a JWT.
func (vc VerifiableCredential) JWT() jwt.Token {
	if vc.token == nil {
		return nil
	}
	token, _ := vc.token.Clone()
	return token
}

// ValidAt returns true if
// - t >= IssuanceDate and ValidFrom
// - t <= ExpirationDate and ValidUntil
// For any value that is missing, the evaluation defaults to true
func (vc VerifiableCredential) ValidAt(t time.Time) bool {
	// IssuanceDate is a required field, but will default to the zero value when missing. (when ValidFrom != nil)
	// t > IssuanceDate
	if vc.IssuanceDate != nil && t.Before(*vc.IssuanceDate) {
		return false
	}
	// t > ValidFrom
	if vc.ValidFrom != nil && t.Before(*vc.ValidFrom) {
		return false
	}
	// t < ExpirationDate
	if vc.ExpirationDate != nil && t.After(*vc.ExpirationDate) {
		return false
	}
	// t < ValidUntil
	if vc.ValidUntil != nil && t.After(*vc.ValidUntil) {
		return false
	}
	// valid
	return true
}

// CredentialStatus contains the required fields ID and Type, and the raw data for unmarshalling into a custom type.
type CredentialStatus struct {
	ID   ssi.URI `json:"id"`
	Type string  `json:"type"`
	raw  []byte
}

func (cs *CredentialStatus) UnmarshalJSON(input []byte) error {
	type alias *CredentialStatus
	a := alias(cs)
	err := json.Unmarshal(input, a)
	if err != nil {
		return err
	}

	// keep compacted copy of the input
	buf := new(bytes.Buffer)
	if err = json.Compact(buf, input); err != nil {
		// should never happen, already parsed as valid json
		return err
	}
	cs.raw = buf.Bytes()
	return nil
}

// Raw returns a copy of the underlying credentialStatus data as set during UnmarshalJSON.
// This can be used to marshal the data into a custom status credential type.
func (cs *CredentialStatus) Raw() []byte {
	if cs.raw == nil {
		return nil
	}
	cp := make([]byte, len(cs.raw))
	copy(cp, cs.raw)
	return cp
}

// CredentialStatuses returns VerifiableCredential.CredentialStatus marshalled into a CredentialStatus slice.
func (vc VerifiableCredential) CredentialStatuses() ([]CredentialStatus, error) {
	var statuses []CredentialStatus
	if err := vc.UnmarshalCredentialStatus(&statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

// Proofs returns the basic proofs for this credential. For specific proof contents, UnmarshalProofValue must be used.
func (vc VerifiableCredential) Proofs() ([]Proof, error) {
	var (
		target []Proof
		err    error
		asJSON []byte
	)
	asJSON, err = json.Marshal(vc.Proof)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(asJSON, &target)
	return target, err
}

func (vc VerifiableCredential) MarshalJSON() ([]byte, error) {
	if vc.format == JWTCredentialProofFormat {
		// Marshal as JSON string
		return json.Marshal(vc.raw) // raw is only set by the parse function
	}
	// Must be a JSON-LD credential
	type alias VerifiableCredential
	tmp := alias(vc)
	return json.Marshal(tmp)
}

func (vc *VerifiableCredential) UnmarshalJSON(b []byte) error {
	var str string
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
	} else {
		str = string(b)
	}
	credential, err := ParseVerifiableCredential(str)
	if err == nil {
		*vc = *credential
	}
	return err
}

// UnmarshalProofValue unmarshalls the proof to the given proof type. Always pass a slice as target since there could be multiple proofs.
// Each proof will result in a value, where null values may exist when the proof doesn't have the json member.
func (vc VerifiableCredential) UnmarshalProofValue(target interface{}) error {
	return unmarshalAnySliceToTarget(vc.Proof, target)
}

// UnmarshalCredentialSubject unmarshalls the credentialSubject to the given credentialSubject type. Always pass a slice as target.
func (vc VerifiableCredential) UnmarshalCredentialSubject(target interface{}) error {
	return unmarshalAnySliceToTarget(vc.CredentialSubject, target)
}

// UnmarshalCredentialStatus unmarshalls the credentialStatus field to the provided target. Always pass a slice as target.
func (vc VerifiableCredential) UnmarshalCredentialStatus(target any) error {
	return unmarshalAnySliceToTarget(vc.CredentialStatus, target)
}

func unmarshalAnySliceToTarget(s []any, target any) error {
	if asJSON, err := json.Marshal(s); err != nil {
		return err
	} else {
		return json.Unmarshal(asJSON, target)
	}
}

// SubjectDID returns the credential subject's ID as DID (credentialSubject.id).
// If there are multiple subjects, all subjects must have the same ID.
// It returns an error when:
// - there are no credential subjects,
// - the ID is not a valid DID
// - all subject IDs are empty
// - not all subjects have the same ID
func (vc VerifiableCredential) SubjectDID() (*did.DID, error) {
	if len(vc.CredentialSubject) < 1 {
		return nil, errors.New("unable to get subject DID from VC: there must be at least 1 credentialSubject")
	}
	type credentialSubject struct {
		ID did.DID `json:"id"`
	}
	var subjects []credentialSubject
	err := vc.UnmarshalCredentialSubject(&subjects)
	if err != nil {
		return nil, fmt.Errorf("unable to get subject DID from VC: %w", err)
	}
	// Assert all credentials share the same subject
	subjectID := subjects[0].ID
	for _, subject := range subjects {
		if !subjectID.Equals(subject.ID) {
			return nil, errors.New("unable to get subject DID from VC: credential subjects have the same ID")
		}
	}
	if subjectID.Empty() {
		return nil, fmt.Errorf("unable to get subject DID from VC: %w", errCredentialSubjectWithoutID)
	}
	return &subjectID, nil
}

// IsType returns true when a credential contains the requested type
func (vc VerifiableCredential) IsType(vcType ssi.URI) bool {
	for _, t := range vc.Type {
		if t.String() == vcType.String() {
			return true
		}
	}

	return false
}

// ContainsContext returns true when a credential contains the requested context
func (vc VerifiableCredential) ContainsContext(context ssi.URI) bool {
	for _, c := range vc.Context {
		if c.String() == context.String() {
			return true
		}
	}

	return false
}

type JWTSigner func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error)

// CreateJWTVerifiableCredential creates a JWT Verifiable Credential from the given credential template.
// For signing the actual JWT it calls the given signer, which must return the created JWT in string format.
// Note: the signer is responsible for adding the right key claims (e.g. `kid`).
func CreateJWTVerifiableCredential(ctx context.Context, template VerifiableCredential, signer JWTSigner) (*VerifiableCredential, error) {
	subjectDID, err := template.SubjectDID()
	if err != nil {
		return nil, err
	}
	headers := map[string]interface{}{
		jws.TypeKey: "JWT",
	}
	claims := map[string]interface{}{
		jwt.IssuerKey:  template.Issuer.String(),
		jwt.SubjectKey: subjectDID.String(),
		"vc": map[string]interface{}{
			"@context":          template.Context,
			"type":              template.Type,
			"credentialSubject": template.CredentialSubject,
		},
	}
	if template.ID != nil {
		claims[jwt.JwtIDKey] = template.ID.String()
	}
	if template.IssuanceDate != nil {
		claims[jwt.NotBeforeKey] = *template.IssuanceDate
	}
	if template.ExpirationDate != nil {
		claims[jwt.ExpirationKey] = *template.ExpirationDate
	}
	if template.ValidFrom != nil || template.ValidUntil != nil {
		// parseJWTCredential maps ValidFrom/ValidUntil to IssuanceDate/ExpirationDate,
		// so a template using ValidFrom/ValidUntil would not match the final VC
		return nil, errors.New("cannot use validFrom/validUntil to generate JWT-VCs")
	}
	token, err := signer(ctx, claims, headers)
	if err != nil {
		return nil, fmt.Errorf("unable to sign JWT credential: %w", err)
	}
	return parseJWTCredential(token)
}
