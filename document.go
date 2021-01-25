package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/internal/marshal"
)

// Document represents a DID Document as specified by the DID Core specification (https://www.w3.org/TR/did-core/).
type Document struct {
	Context            []URI                      `json:"context"`
	ID                 DID                        `json:"id"`
	Controller         []DID                      `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod       `json:"verificationMethod,omitempty"`
	Authentication     []VerificationRelationship `json:"authentication,omitempty"`
	AssertionMethod    []VerificationRelationship `json:"assertionMethod,omitempty"`
	Service            []Service                  `json:"service,omitempty"`
}

func (d Document) MarshalJSON() ([]byte, error) {
	type alias Document
	tmp := alias(d)
	if data, err := json.Marshal(tmp); err != nil {
		return nil, err
	} else {
		return marshal.NormalizeDocument(data, marshal.Unplural(contextKey), marshal.Unplural(controllerKey))
	}
}

func (d *Document) UnmarshalJSON(b []byte) error {
	type Alias Document
	normalizedDoc, err := marshal.NormalizeDocument(b, standardAliases, pluralContext, marshal.Plural(controllerKey))
	if err != nil {
		return err
	}
	doc := Alias{}
	err = json.Unmarshal(normalizedDoc, &doc)
	if err != nil {
		return err
	}
	*d = (Document)(doc)

	if err = resolveVerificationRelationships(d.Authentication, d.VerificationMethod); err != nil {
		return fmt.Errorf("unable to resolve all '%s' references: %w", authenticationKey, err)
	}
	if err = resolveVerificationRelationships(d.AssertionMethod, d.VerificationMethod); err != nil {
		return fmt.Errorf("unable to resolve all '%s' references: %w", assertionMethodKey, err)
	}
	return nil
}

func (d Document) Copy() Document {
	return d
}

// Service represents a DID Service as specified by the DID Core specification (https://www.w3.org/TR/did-core/#service-endpoints).
type Service struct {
	ID              URI         `json:"id"`
	Type            string      `json:"type,omitempty"`
	ServiceEndpoint interface{} `json:"serviceEndpoint,omitempty"`
}

func (s Service) MarshalJSON() ([]byte, error) {
	type alias Service
	tmp := alias(s)
	if data, err := json.Marshal(tmp); err != nil {
		return nil, err
	} else {
		return marshal.NormalizeDocument(data, marshal.Unplural(serviceEndpointKey))
	}
}

func (s *Service) UnmarshalJSON(data []byte) error {
	normalizedData, err := marshal.NormalizeDocument(data, standardAliases, pluralContext, marshal.PluralValueOrMap(serviceEndpointKey))
	if err != nil {
		return err
	}
	type alias Service
	var result alias
	if err := json.Unmarshal(normalizedData, &result); err != nil {
		return err
	}
	*s = (Service)(result)
	return nil
}

// Unmarshal unmarshals the service endpoint into a domain-specific type.
func (s Service) UnmarshalServiceEndpoint(target interface{}) error {
	if asJSON, err := json.Marshal(s.ServiceEndpoint); err != nil {
		return err
	} else {
		return json.Unmarshal(asJSON, target)
	}
}

// VerificationMethod represents a DID Verification Method as specified by the DID Core specification (https://www.w3.org/TR/did-core/#verification-methods).
type VerificationMethod struct {
	ID           URI    `json:"id"`
	Type         string `json:"type,omitempty"`
	Controller   DID    `json:"controller,omitempty"`
	parsedJWK    jwk.Key
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk,omitempty"`
}

// JWK returns the key described by the VerificationMethod as JSON Web Key.
func (v VerificationMethod) JWK() jwk.Key {
	return v.parsedJWK
}

// VerificationRelationship represents the usage of a VerificationMethod e.g. in authentication, assertionMethod, or keyAgreement.
type VerificationRelationship struct {
	*VerificationMethod
	reference URI
}

func (v VerificationRelationship) MarshalJSON() ([]byte, error) {
	if v.reference.Scheme == "" {
		return json.Marshal(*v.VerificationMethod)
	} else {
		return json.Marshal(v.reference)
	}
}

func (v *VerificationRelationship) UnmarshalJSON(b []byte) error {
	// try to figure out if the item is an object of a string
	type Alias VerificationRelationship
	switch b[0] {
	case '{':
		tmp := Alias{VerificationMethod: &VerificationMethod{}}
		err := json.Unmarshal(b, &tmp)
		if err != nil {
			return fmt.Errorf("could not parse verificationRelation method: %w", err)
		}
		*v = (VerificationRelationship)(tmp)
	case '"':
		err := json.Unmarshal(b, &v.reference)
		if err != nil {
			return fmt.Errorf("could not parse verificationRelation key relation DID: %w", err)
		}
	default:
		return errors.New("verificationRelation is invalid")
	}
	return nil
}

func (v *VerificationMethod) UnmarshalJSON(bytes []byte) error {
	type Alias VerificationMethod
	tmp := Alias{}
	err := json.Unmarshal(bytes, &tmp)
	if err != nil {
		return err
	}
	*v = (VerificationMethod)(tmp)
	if v.PublicKeyJwk != nil {
		jwkAsJSON, _ := json.Marshal(v.PublicKeyJwk)
		key, err := jwk.ParseKey(jwkAsJSON)
		if err != nil {
			return fmt.Errorf("could not parse verificationMethod: invalid publickeyJwk: %w", err)
		}
		v.parsedJWK = key
	}
	return nil
}

func resolveVerificationRelationships(relationships []VerificationRelationship, methods []VerificationMethod) error {
	for i, relationship := range relationships {
		if relationship.reference.Scheme == "" {
			continue
		}
		if resolved := resolveVerificationRelationship(relationship.reference, methods); resolved == nil {
			return fmt.Errorf("unable to resolve %s: %s", verificationMethodKey, relationship.reference.String())
		} else {
			relationships[i] = *resolved
			relationships[i].reference = relationship.reference
		}
	}
	return nil
}

func resolveVerificationRelationship(reference URI, methods []VerificationMethod) *VerificationRelationship {
	for _, method := range methods {
		if method.ID == reference {
			return &VerificationRelationship{VerificationMethod: &method}
		}
	}
	return nil
}
