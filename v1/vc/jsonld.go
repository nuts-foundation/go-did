package vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/v1/ld"
	libld "github.com/piprate/json-gold/ld"
	"strings"
)

func Parse(raw string, documentLoader ld.DocumentLoader) (VerifiableCredential, error) {
	if strings.HasPrefix(raw, "ey") {
		return parseJWT(raw)
	} else {
		// JSON-LD
		return parseJSONLD(raw, documentLoader)
	}
}

func parseJWT(raw string) (VerifiableCredential, error) {
	token, err := jwt.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("jwt parse: %w", err)
	}
	return JWTVerifiableCredential{
		token: token,
	}
}

func parseJSONLD(raw string, documentLoader ld.DocumentLoader) (VerifiableCredential, error) {
	document, err := libld.DocumentFromReader(bytes.NewReader([]byte(raw)))
	if err != nil {
		return nil, fmt.Errorf("jsonld read: %w", err)
	}

	processor := libld.NewJsonLdProcessor()
	options := libld.NewJsonLdOptions("")
	options.DocumentLoader = documentLoader
	options.SafeMode = true

	expanded, err := processor.Expand(document, options)
	if err != nil {
		return nil, fmt.Errorf("jsonld expand: %w", err)
	}
	if len(expanded) != 1 {
		return nil, fmt.Errorf("jsonld expand: expected 1 document")
	}
	var result LDVerifiableCredential
	result.Object = ld.ToObject(expanded[0]).(ld.BaseObject)
	result.context = unmarshalContext([]byte(raw))
	return &result, nil
}

func unmarshalContext(input []byte) []interface{} {
	type context struct {
		Context []interface{} `json:"@context"`
	}
	var c context
	_ = json.Unmarshal(input, &c)
	return c.Context
}

func ToIssuer(obj interface{}) Issuer {
	asSlice, ok := obj.([]interface{})
	if !ok {
		return nil
	}
	// should be only 1
	for _, curr := range asSlice {
		return &LDIssuer{
			Object:  ld.ToObject(curr).(ld.BaseObject),
			context: nil,
		}
	}
	return nil
}

func ToCredentialSubjects(obj interface{}) []CredentialSubject {
	asSlice, ok := obj.([]interface{})
	if !ok {
		return nil
	}
	var result []CredentialSubject
	for _, raw := range asSlice {
		result = append(result, &LDCredentialSubject{
			Object:  ld.ToObject(raw).(ld.BaseObject),
			context: nil,
		})
	}
	return result
}
