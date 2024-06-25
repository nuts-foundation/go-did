package vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/v1/ld"
	libld "github.com/piprate/json-gold/ld"
)

func Parse(raw string, documentLoader ld.DocumentLoader) (VerifiableCredential, error) {
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
