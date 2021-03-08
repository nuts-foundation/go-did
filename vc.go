package did

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/internal/marshal"
)

// VerifiableCredential represents a credential as defined by the Verifiable Credentials Data Model 1.0 specification (https://www.w3.org/TR/vc-data-model/).
type VerifiableCredential struct {
	// Context defines the json-ld context to dereference the URIs
	Context []URI `json:"@context"`
	// ID is an unique identifier for the credential. It is optional
	ID *URI `json:"id,omitempty"`
	// Type holds multiplte types for a credential. A credential must always have the 'VerifiableCredential' type.
	Type []URI `json:"type"`
	// Issuer refers to the party that issued the credential
	Issuer URI `json:"issuer"`
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
}

// CredentialStatus defines the method on how to determine a credential is revoked.
type CredentialStatus struct {
	ID   url.URL `json:"id"`
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
		return marshal.NormalizeDocument(data, pluralContext, marshal.Unplural(credentialSubjectKey), marshal.Unplural(proofKey))
	}
}

func (vc *VerifiableCredential) UnmarshalJSON(b []byte) error {
	type Alias VerifiableCredential
	normalizedVC, err := marshal.NormalizeDocument(b, pluralContext, marshal.Plural(credentialSubjectKey), marshal.Plural(proofKey))
	if err != nil {
		return err
	}
	tmp := Alias{}
	err = json.Unmarshal(normalizedVC, &tmp)
	if err != nil {
		return err
	}
	*vc = (VerifiableCredential)(tmp)
	return nil
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
