package did

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/shengdoushi/base58"

	"github.com/nuts-foundation/go-did/internal/marshal"
)

// Document represents a DID Document as specified by the DID Core specification (https://www.w3.org/TR/did-core/).
type Document struct {
	Context            []URI                      `json:"@context"`
	ID                 DID                        `json:"id"`
	Controller         []DID                      `json:"controller,omitempty"`
	VerificationMethod VerificationMethods        `json:"verificationMethod,omitempty"`
	Authentication     []VerificationRelationship `json:"authentication,omitempty"`
	AssertionMethod    []VerificationRelationship `json:"assertionMethod,omitempty"`
	Service            []Service                  `json:"service,omitempty"`
}

type VerificationMethods []*VerificationMethod

// Find the first VerificationMethod which matches the provided DID.
// Returns nil when not found
func (vms VerificationMethods) FindByID(id DID) *VerificationMethod {
	for _, vm := range vms {
		if vm.ID.Equals(id) {
			return vm
		}
	}
	return nil
}

// Ensures the verificationMethods does not have a verification method with the provided DID.
// If a verificationMethod was found with the given DID, it will be returned
func (vms *VerificationMethods) Remove(id DID) *VerificationMethod {
	var (
		filteredVMS []*VerificationMethod
		foundVM     *VerificationMethod
	)
	for _, vm := range *vms {
		if !vm.ID.Equals(id) {
			filteredVMS = append(filteredVMS, vm)
		} else {
			foundVM = vm
		}
	}
	*vms = filteredVMS
	return foundVM
}

// Add adds a verificationMethod to the verificationMethods if it not already present.
func (vms *VerificationMethods) Add(v *VerificationMethod) {
	for _, ptr := range *vms {
		// check if the pointer is already in the list
		if ptr == v {
			return
		}
		// check if the actual ids match?
		if ptr.ID.Equals(v.ID) {
			return
		}
	}
	*vms = append(*vms, v)
}

// Add a VerificationMethod as AssertionMethod
// If the controller is not set, it will be set to the documents ID
func (d *Document) AddAssertionMethod(v *VerificationMethod) {
	d.VerificationMethod.Add(v)
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.AssertionMethod = append(d.AssertionMethod, VerificationRelationship{
		VerificationMethod: v,
		reference:          v.ID,
	})
}

// AddAuthenticationMethod adds a VerificationMethod as AuthenticationMethod
// If the controller is not set, it will be set to the document's ID
func (d *Document) AddAuthenticationMethod(v *VerificationMethod) {
	d.VerificationMethod.Add(v)
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.Authentication = append(d.Authentication, VerificationRelationship{
		VerificationMethod: v,
		reference:          v.ID,
	})
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
	normalizedDoc, err := marshal.NormalizeDocument(b, pluralContext, marshal.Plural(controllerKey))
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
	normalizedData, err := marshal.NormalizeDocument(data, pluralContext, marshal.PluralValueOrMap(serviceEndpointKey))
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

// Unmarshal unmarshalls the service endpoint into a domain-specific type.
func (s Service) UnmarshalServiceEndpoint(target interface{}) error {
	var valueToMarshal interface{}
	if asSlice, ok := s.ServiceEndpoint.([]interface{}); ok && len(asSlice) == 1 {
		valueToMarshal = asSlice[0]
	} else {
		valueToMarshal = s.ServiceEndpoint
	}
	if asJSON, err := json.Marshal(valueToMarshal); err != nil {
		return err
	} else {
		return json.Unmarshal(asJSON, target)
	}
}

// VerificationMethod represents a DID Verification Method as specified by the DID Core specification (https://www.w3.org/TR/did-core/#verification-methods).
type VerificationMethod struct {
	ID              DID                    `json:"id"`
	Type            KeyType                `json:"type,omitempty"`
	Controller      DID                    `json:"controller,omitempty"`
	PublicKeyJwk    map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyBase58 string                 `json:"publicKeyBase58,omitempty"`
}

// NewVerificationMethod is a convenience method to easily create verificationMethods based on a set of given params.
// It automatically encodes the provided public key based on the keyType.
func NewVerificationMethod(id DID, keyType KeyType, controller DID, key crypto.PublicKey) (*VerificationMethod, error) {
	vm := &VerificationMethod{
		ID:         id,
		Type:       keyType,
		Controller: controller,
	}

	if keyType == JsonWebKey2020 {
		keyAsJWK, err := jwk.New(key)
		if err != nil {
			return nil, err
		}
		jwkAsMap, err := keyAsJWK.AsMap(context.Background())
		if err != nil {
			return nil, err
		}
		vm.PublicKeyJwk = jwkAsMap
	}
	if keyType == ED25519VerificationKey2018 {
		ed25519Key, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("wrong key type")
		}
		encodedKey := base58.Encode(ed25519Key, base58.BitcoinAlphabet)
		vm.PublicKeyBase58 = encodedKey
	}

	return vm, nil
}

// JWK returns the key described by the VerificationMethod as JSON Web Key.
func (v VerificationMethod) JWK() (jwk.Key, error) {
	if v.PublicKeyJwk == nil {
		return nil, nil
	}
	jwkAsJSON, _ := json.Marshal(v.PublicKeyJwk)
	key, err := jwk.ParseKey(jwkAsJSON)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}
	return key, nil
}

func (v VerificationMethod) PublicKey() (crypto.PublicKey, error) {
	var pubKey crypto.PublicKey
	switch v.Type {
	case ED25519VerificationKey2018:
		keyBytes, err := base58.Decode(v.PublicKeyBase58, base58.BitcoinAlphabet)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(keyBytes), err
	case JsonWebKey2020:
		keyAsJWK, err := v.JWK()
		if err != nil {
			return nil, err
		}
		err = keyAsJWK.Raw(&pubKey)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	}
	return nil, errors.New("unsupported verification method type")
}

// VerificationRelationship represents the usage of a VerificationMethod e.g. in authentication, assertionMethod, or keyAgreement.
type VerificationRelationship struct {
	*VerificationMethod
	reference DID
}

func (v VerificationRelationship) MarshalJSON() ([]byte, error) {
	if v.reference.Empty() {
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
	return nil
}

func resolveVerificationRelationships(relationships []VerificationRelationship, methods []*VerificationMethod) error {
	for i, relationship := range relationships {
		if relationship.reference.Empty() {
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

func resolveVerificationRelationship(reference DID, methods []*VerificationMethod) *VerificationRelationship {
	for _, method := range methods {
		if method.ID.Equals(reference) {
			return &VerificationRelationship{VerificationMethod: method}
		}
	}
	return nil
}
