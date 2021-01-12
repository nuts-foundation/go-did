package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/did/internal"
	"net/url"
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

// Service represents a DID Service Endpoint as specified by the DID Core specification (https://www.w3.org/TR/did-core/#service-endpoints).
type Service struct {
	ID   URI
	Type string
	// EndpointURL contains the service endpoint URLs if set. If this field is empty, the service should contain
	// properties as serviceEndpoint (see EndpointProperties). You can also check this using IsURL.
	EndpointURL []url.URL `json:"-"`
	// EndpointProperties contains the service endpoint proeprties if set. If this field is empty, the service should contain
	// an absolute URL (or multiple) as serviceEndpoint (see EndpointURL). You can also check this using IsURL.
	EndpointProperties map[string]interface{} `json:"-"`
}

// IsURL returns whether the service endpoint contains an absolute URL or properties. If it returns true, `EndpointURL`
// contains the value to be used. Otherwise applications should use `EndpointProperties` directly or unmarshal it into
// a more specific type using `UnmarshalEndpoint`.
func (s Service) IsURL() bool {
	return len(s.EndpointURL) > 0
}

func (s *Service) UnmarshalJSON(data []byte) error {
	normalizedData, err := internal.NormalizeDocument(data, standardAliases, pluralContext, internal.PluralValueOrMap(serviceEndpointKey))
	if err != nil {
		return err
	}
	type alias Service
	var result alias
	if err := json.Unmarshal(normalizedData, &result); err != nil {
		return err
	}
	asMap := make(map[string]interface{})
	if err := json.Unmarshal(normalizedData, &asMap); err != nil {
		return err
	}
	if asMap[serviceEndpointKey] != nil {
		if absoluteEPs, ok := asMap[serviceEndpointKey].([]interface{}); ok {
			if result.EndpointURL, err = parseURLs(absoluteEPs); err != nil {
				return fmt.Errorf("invalid service endpoint URL: %w", err)
			}
		} else {
			result.EndpointProperties = asMap[serviceEndpointKey].(map[string]interface{})
		}
	}
	*s = (Service)(result)
	return nil
}

// Unmarshal unmarshals the endpoint properties into a domain-specific type. Can only be used when `IsURL` returns false.
func (s Service) UnmarshalEndpoint(target interface{}) error {
	if s.IsURL() {
		return errors.New("service endpoint contains a URL so can't be unmarshalled")
	}
	if asJSON, err := json.Marshal(s.EndpointProperties); err != nil {
		return err
	} else {
		return json.Unmarshal(asJSON, target)
	}
}

// VerificationMethod represents a DID Verification Method as specified by the DID Core specification (https://www.w3.org/TR/did-core/#verification-methods).
type VerificationMethod struct {
	ID           URI
	Type         string
	Controller   DID
	parsedJWK    jwk.Key
	PublicKeyJwk map[string]interface{}
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
	normalizedDoc, err := internal.NormalizeDocument(b, standardAliases, pluralContext,
		internal.Plural(controllerKey), internal.Plural(verificationMethodKey), internal.Plural(authenticationKey),
		internal.Plural(assertionMethodKey), internal.Plural(serviceKey))
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

func resolveVerificationRelationships(relationships []VerificationRelationship, methods []VerificationMethod) error {
	for i, relationship := range relationships {
		if relationship.reference.Scheme == "" {
			continue
		}
		if resolved := resolveVerificationRelationship(relationship.reference, methods); resolved == nil {
			return fmt.Errorf("unable to resolve %s: %s", verificationMethodKey, relationship.reference.String())
		} else {
			relationships[i] = *resolved
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
