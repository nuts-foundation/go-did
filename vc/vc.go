package vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwt"
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
	// JWTCredentialsProofFormat is the format for JWT based credentials.
	JWTCredentialsProofFormat = "jwt_vc"
)

var errCredentialSubjectWithoutID = errors.New("credential subjects have no ID")

// ParseVerifiableCredential parses a Verifiable Credential from a string, which can be either in JSON-LD or JWT format.
// If the format is JWT, the parsed token can be retrieved using JWT().
func ParseVerifiableCredential(raw string) (*VerifiableCredential, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		// Assume JSON-LD format
		type Alias VerifiableCredential
		normalizedVC, err := marshal.NormalizeDocument([]byte(raw), pluralContext, marshal.Plural(typeKey), marshal.Plural(credentialSubjectKey), marshal.Plural(proofKey))
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
	} else {
		// Assume JWT format
		token, err := jwt.Parse([]byte(raw))
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
		exp := token.Expiration()
		result.ExpirationDate = &exp
		// parse iss
		if iss, err := parseURIClaim(token, jwt.IssuerKey); err != nil {
			return nil, err
		} else if iss != nil {
			result.Issuer = *iss
		}
		// parse nbf
		result.IssuanceDate = token.NotBefore()
		// parse sub
		if token.Subject() != "" {
			for _, credentialSubjectInterf := range result.CredentialSubject {
				credentialSubject, isMap := credentialSubjectInterf.(map[string]interface{})
				if isMap {
					credentialSubject["id"] = token.Subject()
				}
			}
		}
		var subject string
		if subjectDID, err := result.SubjectDID(); err != nil {
			// credentialSubject.id is optional
			if !errors.Is(err, errCredentialSubjectWithoutID) {
				return nil, fmt.Errorf("invalid JWT 'sub' claim: %w", err)
			}
		} else if subjectDID != nil {
			subject = subjectDID.String()
		}
		if token.Subject() != subject {
			return nil, errors.New("invalid JWT 'sub' claim: must equal credentialSubject.id")
		}
		// parse jti
		if jti, err := parseURIClaim(token, jwt.JwtIDKey); err != nil {
			return nil, err
		} else if jti != nil {
			result.ID = jti
		}
		result.format = JWTCredentialsProofFormat
		result.raw = raw
		result.token = token
		return &result, nil
	}
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
	// IssuanceDate is a rfc3339 formatted datetime.
	IssuanceDate time.Time `json:"issuanceDate"`
	// ExpirationDate is a rfc3339 formatted datetime. It is optional
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
	// CredentialStatus holds information on how the credential can be revoked. It is optional
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty"`
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

// CredentialStatus defines the method on how to determine a credential is revoked.
type CredentialStatus struct {
	ID   ssi.URI `json:"id"`
	Type string  `json:"type"`
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
	type alias VerifiableCredential
	tmp := alias(vc)
	if data, err := json.Marshal(tmp); err != nil {
		return nil, err
	} else {
		return marshal.NormalizeDocument(data, pluralContext, marshal.Unplural(typeKey), marshal.Unplural(credentialSubjectKey), marshal.Unplural(proofKey))
	}
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
	if asJSON, err := json.Marshal(vc.Proof); err != nil {
		return err
	} else {
		return json.Unmarshal(asJSON, target)
	}
}

// UnmarshalCredentialSubject unmarshalls the credentialSubject to the given credentialSubject type. Always pass a slice as target.
func (vc VerifiableCredential) UnmarshalCredentialSubject(target interface{}) error {
	if asJSON, err := json.Marshal(vc.CredentialSubject); err != nil {
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
