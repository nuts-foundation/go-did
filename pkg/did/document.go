package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/golang-didparser/marshaling"
	"github.com/nuts-foundation/golang-didparser/pkg"
)

// Document represents a DID Document as specified by the DID Core specification (https://www.w3.org/TR/did-core/).
type Document struct {
	Context            []pkg.URI                  `json:"@context"`
	ID                 DID                        `json:"id"`
	Controller         []DID                      `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod       `json:"verificationMethod,omitempty"`
	Authentication     []VerificationRelationship `json:"authentication,omitempty"`
	AssertionMethod    []VerificationRelationship `json:"assertionMethod,omitempty"`
	Service            []Service                  `json:"service,omitempty"`
}

// Service represents a DID Service Endpoint as specified by the DID Core specification (https://www.w3.org/TR/did-core/#service-endpoints).
type Service struct {
	ID   DID
	Type string
}

// VerificationMethod represents a DID Verification Method as specified by the DID Core specification (https://www.w3.org/TR/did-core/#verification-methods).
type VerificationMethod struct {
	ID           DID
	Type         string
	Controller   DID
	parsedJWK    jwk.Key
	PublicKeyJwk map[string]interface{}
}

// JWK returns the key described by the VerificationMethod as JSON Web Key.
func (v VerificationMethod) JWK() jwk.Key {
	return v.parsedJWK
}

// VerificationRelationship represents the usage of a VerificationMethod  e.g. in authentication, assertionMethod, or keyAgreement.
type VerificationRelationship struct {
	*VerificationMethod
	reference DID
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

func (d *Document) UnmarshalJSON(b []byte) error {
	type Alias Document
	normalizedDoc, err := marshaling.NormalizeDocument(b, "@context", "controller")
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
		return fmt.Errorf("unable to resolve all 'authentication' references: %w", err)
	}
	if err = resolveVerificationRelationships(d.AssertionMethod, d.VerificationMethod); err != nil {
		return fmt.Errorf("unable to resolve all could not resolve all 'assertionMethod' references: %w", err)
	}
	return nil
}

func resolveVerificationRelationships(relationships []VerificationRelationship, methods []VerificationMethod) error {
	for i, relationship := range relationships {
		if relationship.reference.Empty() {
			continue
		}
		if resolved := resolveVerificationRelationship(relationship.reference, methods); resolved == nil {
			return fmt.Errorf("unable to resolve verificationMethod: %s", relationship.reference)
		} else {
			relationships[i] = *resolved
		}
	}
	return nil
}

func resolveVerificationRelationship(reference DID, methods []VerificationMethod) *VerificationRelationship {
	for _, method := range methods {
		if method.ID.Equals(reference) {
			return &VerificationRelationship{VerificationMethod: &method}
		}
	}
	return nil
}
