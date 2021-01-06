package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"net/url"
)

type URI string

func (v URI) String() string {
	return string(v)
}

func (v *URI) UnmarshalJSON(bytes []byte) error {
	var value string
	if err := json.Unmarshal(bytes, &value); err != nil {
		return err
	}
	*v = URI(value)
	return nil
}

type VerificationMethod struct {
	ID           URI
	Type         string
	Controller   URI
	parsedJWK    jwk.Key
	publicKeyJwk map[string]interface{}
}

type VerificationRelationship struct {
	*VerificationMethod
}

type didDocument struct {
	Context            []url.URL
	ID                 URI
	Controllers        []URI `json:"controller"`
	VerificationMethod []VerificationMethod
	Authentication     []VerificationRelationship
	AssertionMethod    []VerificationRelationship
}

func (d *didDocument) UnmarshalJSON(bytes []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		return err
	}

	var err error

	// Parse '@context'
	if str, ok := data["@context"].(string); ok {
		if value, err := url.Parse(str); err != nil {
			return err
		} else {
			d.Context = []url.URL{*value}
		}
	} else if strs, ok := data["@context"].([]interface{}); ok {
		value := make([]url.URL, len(strs))
		for i := 0; i < len(strs); i++ {
			if current, err := url.Parse(fmt.Sprintf("%s", strs[i])); err != nil {
				return err
			} else {
				value[i] = *current
			}
		}
		d.Context = value
	} else {
		return errors.New("DID '@context' is invalid")
	}

	// Parse 'id'
	if id, ok := data["id"].(string); ok {
		d.ID = URI(id)
	} else {
		return errors.New("DID 'id' is invalid")
	}

	// Parse 'controller'
	if controller, ok := data["controller"].(string); ok {
		if d.Controllers, err = ParseDIDs(controller); err != nil {
			return err
		}
	} else if controllers, ok := data["controller"].([]interface{}); ok {
		if d.Controllers, err = ParseDIDs(controllers...); err != nil {
			return err
		}
	} else if data["controller"] == nil {
		// If 'controller' does not exist, fallback to document ID
		d.Controllers = []URI{d.ID}
	} else {
		return errors.New("DID 'controller' is invalid")
	}

	// Parse 'verificationMethod'
	if verificationMethods, ok := data["verificationMethod"].([]interface{}); ok {
		d.VerificationMethod = make([]VerificationMethod, len(verificationMethods))
		for i := 0; i < len(verificationMethods); i++ {
			if value, err := parseVerificationMethod(verificationMethods[i]); err != nil {
				return fmt.Errorf("unable to parse verificationMethod[%d]: %w", i, err)
			} else {
				d.VerificationMethod[i] = *value
			}
		}
	} else if data["verificationMethod"] != nil {
		return errors.New("DID 'verificationMethod' is invalid")
	}

	// Parse 'authentication'
	if data["authentication"] != nil {
		if relationships, err := parseVerificationRelationships(data["authentication"], d.VerificationMethod); err != nil {
			return fmt.Errorf("invalid authentication: %w", err)
		} else {
			d.Authentication = relationships
		}
	}

	// Parse 'assertionMethod'
	if data["assertionMethod"] != nil {
		if relationships, err := parseVerificationRelationships(data["assertionMethod"], d.VerificationMethod); err != nil {
			return fmt.Errorf("invalid assertionMethod: %w", err)
		} else {
			d.AssertionMethod = relationships
		}
	}

	return nil
}

func parseVerificationRelationships(input interface{}, verificationMethods []VerificationMethod) ([]VerificationRelationship, error) {
	list, ok := input.([]interface{})
	if !ok {
		return nil, errors.New("expected a list")
	}
	result := make([]VerificationRelationship, len(list))
	for i := 0; i < len(list); i++ {
		if current, ok := list[i].(string); ok {
			method := filterVerificationMethod(URI(current), verificationMethods)
			if method == nil {
				return nil, errors.New("unknown verification method")
			}
			result[i] = VerificationRelationship{
				VerificationMethod: method,
			}
		} else {
			// Embedded verification method, not supported
			return nil, errors.New("only references are supported")
		}
	}
	return result, nil
}

func filterVerificationMethod(id URI, verificationMethods []VerificationMethod) *VerificationMethod {
	for _, method := range verificationMethods {
		if method.ID == id {
			return &method
		}
	}
	return nil
}

func parseVerificationMethod(input interface{}) (*VerificationMethod, error) {
	asMap, ok := input.(map[string]interface{})
	if !ok {
		return nil, errors.New("expected a map")
	}
	result := VerificationMethod{
		ID:         URI(fmt.Sprintf("%s", asMap["id"])),
		Controller: URI(fmt.Sprintf("%s", asMap["controller"])),
		Type:       fmt.Sprintf("%s", asMap["type"]),
	}
	if result.Type != "JsonWebKey2020" {
		return nil, fmt.Errorf("unsupported verification key type: %s", result.Type)
	}
	if asMap["publicKeyJwk"] == nil {
		return nil, errors.New("publicKeyJwk is missing")
	}
	jwkAsJSON, _ := json.Marshal(asMap["publicKeyJwk"])
	if key, err := jwk.ParseKey(jwkAsJSON); err != nil {
		return nil, fmt.Errorf("unable to parse JWK: %w", err)
	} else {
		result.parsedJWK = key
	}
	return &result, nil
}

func ParseDID(input string) (URI, error) {
	return URI(input), nil
}

func ParseDIDs(input ...interface{}) ([]URI, error) {
	result := make([]URI, len(input))
	var err error
	for i := 0; i < len(input); i++ {
		if result[i], err = ParseDID(fmt.Sprintf("%s", input[i])); err != nil {
			return nil, err
		}
	}
	return result, nil
}
