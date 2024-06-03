package did

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/multiformats/go-multibase"
	"strings"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/internal/marshal"
	"github.com/shengdoushi/base58"
)

// ParseDocument parses a DID Document from a string.
func ParseDocument(raw string) (*Document, error) {
	type Alias Document
	normalizedDoc, err := marshal.NormalizeDocument([]byte(raw), pluralContext, marshal.Plural(controllerKey))
	if err != nil {
		return nil, err
	}
	doc := Alias{}
	err = json.Unmarshal(normalizedDoc, &doc)
	if err != nil {
		return nil, err
	}
	d := Document(doc)

	const errMsg = "unable to resolve all '%s' references: %w"
	if err = resolveVerificationRelationships(doc.ID, d.Authentication, d.VerificationMethod); err != nil {
		return nil, fmt.Errorf(errMsg, authenticationKey, err)
	}
	if err = resolveVerificationRelationships(doc.ID, d.AssertionMethod, d.VerificationMethod); err != nil {
		return nil, fmt.Errorf(errMsg, assertionMethodKey, err)
	}
	if err = resolveVerificationRelationships(doc.ID, d.KeyAgreement, d.VerificationMethod); err != nil {
		return nil, fmt.Errorf(errMsg, keyAgreementKey, err)
	}
	if err = resolveVerificationRelationships(doc.ID, d.CapabilityInvocation, d.VerificationMethod); err != nil {
		return nil, fmt.Errorf(errMsg, capabilityInvocationKey, err)
	}
	if err = resolveVerificationRelationships(doc.ID, d.CapabilityDelegation, d.VerificationMethod); err != nil {
		return nil, fmt.Errorf(errMsg, capabilityDelegationKey, err)
	}
	return &d, nil
}

// Document represents a DID Document as specified by the DID Core specification (https://www.w3.org/TR/did-core/).
type Document struct {
	Context              []interface{}             `json:"@context"`
	ID                   DID                       `json:"id"`
	Controller           []DID                     `json:"controller,omitempty"`
	AlsoKnownAs          []ssi.URI                 `json:"alsoKnownAs,omitempty"`
	VerificationMethod   VerificationMethods       `json:"verificationMethod,omitempty"`
	Authentication       VerificationRelationships `json:"authentication,omitempty"`
	AssertionMethod      VerificationRelationships `json:"assertionMethod,omitempty"`
	KeyAgreement         VerificationRelationships `json:"keyAgreement,omitempty"`
	CapabilityInvocation VerificationRelationships `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation VerificationRelationships `json:"capabilityDelegation,omitempty"`
	Service              []Service                 `json:"service,omitempty"`
}

type VerificationMethods []*VerificationMethod

// FindByID find the first VerificationMethod which matches the provided DID.
// Returns nil when not found
func (vms VerificationMethods) FindByID(id DIDURL) *VerificationMethod {
	for _, vm := range vms {
		if vm.ID.Equals(id) {
			return vm
		}
	}
	return nil
}

// remove a VerificationMethod from the slice.
func (vms *VerificationMethods) remove(id DIDURL) {
	var filteredVMS []*VerificationMethod
	for _, vm := range *vms {
		if !vm.ID.Equals(id) {
			filteredVMS = append(filteredVMS, vm)
		}
	}
	*vms = filteredVMS
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

type VerificationRelationships []VerificationRelationship

// FindByID returns the first VerificationRelationship that matches with the id.
// For comparison both the ID of the embedded VerificationMethod and reference is used.
func (vmr VerificationRelationships) FindByID(id DIDURL) *VerificationMethod {
	for _, r := range vmr {
		if r.VerificationMethod != nil {
			if r.VerificationMethod.ID.Equals(id) {
				return r.VerificationMethod
			}
		}
	}
	return nil
}

// Remove removes a VerificationRelationship from the slice.
// If a VerificationRelationship was removed with the given DID, it will be returned
func (vmr *VerificationRelationships) Remove(id DIDURL) *VerificationRelationship {
	var (
		filteredVMRels []VerificationRelationship
		removedRel     *VerificationRelationship
	)
	for _, r := range *vmr {
		if !r.ID.Equals(id) {
			filteredVMRels = append(filteredVMRels, r)
		} else {
			removedRel = &r
		}
	}
	*vmr = filteredVMRels
	return removedRel
}

// Add adds a verificationMethod to a relationship collection.
// When the collection already contains the method it will not be added again.
func (vmr *VerificationRelationships) Add(vm *VerificationMethod) {
	for _, rel := range *vmr {
		if rel.ID.Equals(vm.ID) {
			return
		}
	}
	*vmr = append(*vmr, VerificationRelationship{vm, vm.ID})
}

// RemoveVerificationMethod from the document if present.
// It'll also remove all references to the VerificationMethod
func (d *Document) RemoveVerificationMethod(vmId DIDURL) {
	d.VerificationMethod.remove(vmId)
	d.AssertionMethod.Remove(vmId)
	d.Authentication.Remove(vmId)
	d.CapabilityDelegation.Remove(vmId)
	d.CapabilityInvocation.Remove(vmId)
	d.KeyAgreement.Remove(vmId)
}

// AddAuthenticationMethod adds a VerificationMethod as AuthenticationMethod
// If the controller is not set, it will be set to the document's ID
func (d *Document) AddAuthenticationMethod(v *VerificationMethod) {
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.VerificationMethod.Add(v)
	d.Authentication.Add(v)
}

// AddAssertionMethod adds a VerificationMethod as AssertionMethod
// If the controller is not set, it will be set to the documents ID
func (d *Document) AddAssertionMethod(v *VerificationMethod) {
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.VerificationMethod.Add(v)
	d.AssertionMethod.Add(v)
}

// AddKeyAgreement adds a VerificationMethod as KeyAgreement
// If the controller is not set, it will be set to the document's ID
func (d *Document) AddKeyAgreement(v *VerificationMethod) {
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.VerificationMethod.Add(v)
	d.KeyAgreement.Add(v)
}

// AddCapabilityInvocation adds a VerificationMethod as CapabilityInvocation
// If the controller is not set, it will be set to the document's ID
func (d *Document) AddCapabilityInvocation(v *VerificationMethod) {
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.VerificationMethod.Add(v)
	d.CapabilityInvocation.Add(v)
}

// AddCapabilityDelegation adds a VerificationMethod as CapabilityDelegation
// If the controller is not set, it will be set to the document's ID
func (d *Document) AddCapabilityDelegation(v *VerificationMethod) {
	if v.Controller.Empty() {
		v.Controller = d.ID
	}
	d.VerificationMethod.Add(v)
	d.CapabilityDelegation.Add(v)
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
	document, err := ParseDocument(string(b))
	if err != nil {
		return err
	}
	*d = *document
	return nil
}

// IsController returns whether the given DID is a controller of the DID document.
func (d Document) IsController(controller DID) bool {
	if controller.Empty() {
		return false
	}
	for _, curr := range d.Controller {
		if curr.Equals(controller) {
			return true
		}
	}
	return false
}

// ResolveEndpointURL finds the endpoint with the given type and unmarshalls it as single URL.
// It returns the endpoint ID and URL, or an error if anything went wrong;
// - holder document can't be resolved,
// - service with given type doesn't exist,
// - multiple services match,
// - serviceEndpoint isn't a string.
func (d *Document) ResolveEndpointURL(serviceType string) (endpointID ssi.URI, endpointURL string, err error) {
	var services []Service
	for _, service := range d.Service {
		if service.Type == serviceType {
			services = append(services, service)
		}
	}
	if len(services) == 0 {
		return ssi.URI{}, "", fmt.Errorf("service not found (did=%s, type=%s)", d.ID, serviceType)
	}
	if len(services) > 1 {
		return ssi.URI{}, "", fmt.Errorf("multiple services found (did=%s, type=%s)", d.ID, serviceType)
	}
	err = services[0].UnmarshalServiceEndpoint(&endpointURL)
	if err != nil {
		return ssi.URI{}, "", fmt.Errorf("unable to unmarshal single URL from service (id=%s): %w", services[0].ID.String(), err)
	}
	return services[0].ID, endpointURL, nil
}

// Service represents a DID Service as specified by the DID Core specification (https://www.w3.org/TR/did-core/#service-endpoints).
type Service struct {
	ID              ssi.URI     `json:"id"`
	Type            string      `json:"type,omitempty"`
	ServiceEndpoint interface{} `json:"serviceEndpoint,omitempty"`
}

// UnmarshalServiceEndpoint unmarshalls the service endpoint into a domain-specific type.
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
	ID                 DIDURL      `json:"id"`
	Type               ssi.KeyType `json:"type,omitempty"`
	Controller         DID         `json:"controller,omitempty"`
	PublicKeyMultibase string      `json:"publicKeyMultibase,omitempty"`
	// PublicKeyBase58 is deprecated and should not be used anymore. Use PublicKeyMultibase or PublicKeyJwk instead.
	PublicKeyBase58 string                 `json:"publicKeyBase58,omitempty"`
	PublicKeyJwk    map[string]interface{} `json:"publicKeyJwk,omitempty"`
}

// NewVerificationMethod is a convenience method to easily create verificationMethods based on a set of given params.
// It automatically encodes the provided public key based on the keyType.
func NewVerificationMethod(id DIDURL, keyType ssi.KeyType, controller DID, key crypto.PublicKey) (*VerificationMethod, error) {
	vm := &VerificationMethod{
		ID:         id,
		Type:       keyType,
		Controller: controller,
	}

	if keyType == ssi.JsonWebKey2020 {
		keyAsJWK, err := jwk.FromRaw(key)
		if err != nil {
			return nil, err
		}
		// Convert to JSON and back to fix encoding of key material to make sure
		// an unmarshalled and newly created VerificationMethod are equal on object level.
		// The format of PublicKeyJwk in verificationMethod is a map[string]interface{}.
		// We can't use the Key.AsMap since the values of the map will all be internal jwk lib structs.
		// After unmarshalling all the fields will be map[string]string.
		keyAsJSON, err := json.Marshal(keyAsJWK)
		if err != nil {
			return nil, err
		}
		keyAsMap := map[string]interface{}{}
		json.Unmarshal(keyAsJSON, &keyAsMap)

		vm.PublicKeyJwk = keyAsMap
	}
	if keyType == ssi.ECDSASECP256K1VerificationKey2019 {
		keyAsJWK, err := jwk.FromRaw(key)
		if err != nil {
			return nil, err
		}
		jwkAsMap, err := keyAsJWK.AsMap(context.Background())
		if err != nil {
			return nil, err
		}
		vm.PublicKeyJwk = jwkAsMap
	}
	if keyType == ssi.ED25519VerificationKey2018 || keyType == ssi.ED25519VerificationKey2020  {
		ed25519Key, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("wrong key type")
		}
		encodedKey, err := multibase.Encode(multibase.Base58BTC, ed25519Key)
		if err != nil {
			return nil, err
		}
		vm.PublicKeyMultibase = encodedKey
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
	case ssi.ED25519VerificationKey2018, ssi.ED25519VerificationKey2020:
		var keyBytes []byte
		var err error
		if v.PublicKeyMultibase != "" {
			_, keyBytes, err = multibase.Decode(v.PublicKeyMultibase)
			if err != nil {
				return nil, fmt.Errorf("publicKeyMultibase decode error: %w", err)
			}
		} else if v.PublicKeyBase58 != "" {
			keyBytes, err = base58.Decode(v.PublicKeyBase58, base58.BitcoinAlphabet)
			if err != nil {
				return nil, fmt.Errorf("publicKeyBase58 decode error: %w", err)
			}
		} else {
			return nil, errors.New("expected either publicKeyMultibase or publicKeyBase58 to be set")
		}
		return ed25519.PublicKey(keyBytes), err
	case ssi.ECDSASECP256K1VerificationKey2019:
		if v.PublicKeyJwk == nil {
			return nil, errors.New("missing publicKeyJwk")
		}
		fallthrough
	case ssi.JsonWebKey2020:
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
	reference DIDURL
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
		keyID, err := parseKeyID(b)
		if err != nil {
			return fmt.Errorf("could not parse verificationRelation key relation DID: %w", err)
		}
		v.reference = *keyID
	default:
		return errors.New("verificationRelation is invalid")
	}
	return nil
}

func parseKeyID(b []byte) (*DIDURL, error) {
	var keyIDString string
	err := json.Unmarshal(b, &keyIDString)
	if err != nil {
		return nil, err
	}
	// 2 possible formats:
	// - Fully qualified, includes the DID of the key controller, e.g.: did:example:123456789abcdefghi#key-1
	// - Relative, only includes the key ID, e.g.: #key-1
	if strings.HasPrefix(keyIDString, "#") {
		return &DIDURL{Fragment: keyIDString[1:]}, nil
	}
	return ParseDIDURL(keyIDString)
}

func (v *VerificationMethod) UnmarshalJSON(bytes []byte) error {
	// Use an alias since ID should conform to DID URL syntax, not DID syntax
	type alias struct {
		ID                 string                 `json:"id"`
		Type               ssi.KeyType            `json:"type,omitempty"`
		Controller         DID                    `json:"controller,omitempty"`
		PublicKeyMultibase string                 `json:"publicKeyMultibase,omitempty"`
		PublicKeyBase58    string                 `json:"publicKeyBase58,omitempty"`
		PublicKeyJwk       map[string]interface{} `json:"publicKeyJwk,omitempty"`
	}
	var tmp alias
	if err := json.Unmarshal(bytes, &tmp); err != nil {
		return err
	}

	// publicKeyJWK, publicKeyBase58 and publicKeyMultibase are all mutually exclusive
	countPresent := 0
	if len(tmp.PublicKeyJwk) > 0 {
		countPresent++
	}
	if len(tmp.PublicKeyBase58) > 0 {
		countPresent++
	}
	if len(tmp.PublicKeyMultibase) > 0 {
		countPresent++
	}
	if countPresent > 1 {
		return errors.New("only one of publicKeyJWK, publicKeyBase58 and publicKeyMultibase can be present")
	}

	id, err := ParseDIDURL(tmp.ID)
	if err != nil {
		return fmt.Errorf("invalid id: %w", err)
	}
	*v = VerificationMethod{
		ID:                 *id,
		Type:               tmp.Type,
		Controller:         tmp.Controller,
		PublicKeyMultibase: tmp.PublicKeyMultibase,
		PublicKeyBase58:    tmp.PublicKeyBase58,
		PublicKeyJwk:       tmp.PublicKeyJwk,
	}
	return nil
}

func resolveVerificationRelationships(baseURI DID, relationships []VerificationRelationship, methods []*VerificationMethod) error {
	for i, relationship := range relationships {
		if relationship.reference.Empty() {
			continue
		}
		ref := relativeURLToAbsoluteURL(baseURI, relationship.reference)
		if resolved := resolveVerificationRelationship(baseURI, ref, methods); resolved == nil {
			return fmt.Errorf("unable to resolve %s: %s", verificationMethodKey, relationship.reference.String())
		} else {
			relationships[i] = *resolved
			relationships[i].reference = relationship.reference
		}
	}
	return nil
}

// relativeURLToAbsoluteURL converts the reference to an absolute URL if it is relative.
// This means it copies the base DID to the reference (if not set in the reference).
func relativeURLToAbsoluteURL(baseURI DID, ref DIDURL) DIDURL {
	if ref.ID == "" {
		// reference is relative to base URI (DID subject ID)
		ref.Method = baseURI.Method
		ref.ID = baseURI.ID
	}
	return ref
}

func resolveVerificationRelationship(baseURI DID, reference DIDURL, methods []*VerificationMethod) *VerificationRelationship {
	for _, method := range methods {
		if relativeURLToAbsoluteURL(baseURI, method.ID).Equals(reference) {
			return &VerificationRelationship{VerificationMethod: method}
		}
	}
	return nil
}

func secp256k1Supported() bool {
	for _, alg := range jwa.EllipticCurveAlgorithms() {
		if alg.String() == "secp256k1" {
			return true
		}
	}
	return false
}
