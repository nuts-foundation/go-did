package did

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/internal/marshal"
)

// VerifiableCredential represents a credential as defined by the Verifiable Credentials Data Model 1.0 specification (https://www.w3.org/TR/vc-data-model/).
type VerifiableCredential struct {
	Context            []URI                      `json:"context"`
	ID                 *URI                        `json:"id,omitempty"`
	Type			   []URI					  `json:"type"`
	Issuer			   URI 						  `json:"issuer"`
	IssuanceDate 	   time.Time				  `json:"issuanceDate"`
	ExpirationDate	   *time.Time 				  `json:"expirationDate"`
	CredentialStatus   *CredentialStatus		  `json:"credentialStatus"`
	CredentialSubject  []interface{}			  `json:"credentialSubject"`
	Proof              []interface{}		      `json:"proof"`
}

// CredentialStatus defines the method on how to determine a credential is revoked.
type CredentialStatus struct {
	ID                 url.URL                    `json:"id"`
	Type			   string					  `json:"type"`
}

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
		return marshal.NormalizeDocument(data, marshal.Unplural(contextKey), marshal.Unplural(credentialSubjectKey), marshal.Unplural(proofKey))
	}
}

func (vc *VerifiableCredential) UnmarshalJSON(b []byte) error {
	type Alias VerifiableCredential
	normalizedVC, err := marshal.NormalizeDocument(b, standardAliases, pluralContext, marshal.Plural(credentialSubjectKey), marshal.Plural(proofKey))
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