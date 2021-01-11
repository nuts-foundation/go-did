package vc

import (
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/golang-didparser/marshaling"
	"github.com/nuts-foundation/golang-didparser/pkg"
	"net/url"
	"time"
)

type VerifiableCredential struct {
	Context        []pkg.URI `json:"@context"`
	ID             pkg.URI   `json:"id"`
	Type           []string  `json:"type"`
	Issuer         pkg.URI
	IssuanceDate   time.Time
	ExpirationDate time.Time
	Subject        []StructuredData `json:"credentialSubject"`
	Proof          []Proof          `json:"proof"`
}

func (v *VerifiableCredential) UnmarshalJSON(data []byte) error {
	type Alias VerifiableCredential
	normalizedDoc, err := marshaling.NormalizeDocument(data, "@context", "type", "credentialSubject", "proof")
	if err != nil {
		return err
	}
	doc := Alias{}
	if err = json.Unmarshal(normalizedDoc, &doc); err != nil {
		return err
	}
	*v = (VerifiableCredential)(doc)
	return nil
}

type Proof map[string]interface{}

type StructuredData struct {
	ID         pkg.URI `json:"id"`
	Properties map[string]interface{}
}

func (g *StructuredData) UnmarshalJSON(data []byte) error {
	asMap := make(map[string]interface{}, 5) // Guessed average credential size
	if err := json.Unmarshal(data, &asMap); err != nil {
		return err
	}
	// Parse ID
	if idAsString, ok := asMap["id"].(string); !ok && asMap["id"] != nil {
		return errors.New("'id' isn't a string")
	} else if idAsString == "" {
		return errors.New("'id' is empty")
	} else if idAsURL, err := url.Parse(idAsString); err != nil {
		return err
	} else {
		g.ID = pkg.URI{URL: *idAsURL}
	}
	// Parse properties
	g.Properties = make(map[string]interface{}, 4)
	for key, value := range asMap {
		if key != "id" {
			g.Properties[key] = value
		}
	}
	return nil
}

// Unmarshal tries to unmarshal the data into the given struct. This can be used when an application has
// determined the actual type of the data, to unmarshal it into a struct that represents it better.
func (g StructuredData) Unmarshal(target interface{}) error {
	// We need the 'id' property to be present in the data to be unmarshalled, but we don't want to alter
	// the 'Properties' field of this struct. So we create a copy, which we add 'ID' to, which we use to unmarshal.
	copiedMap := make(map[string]interface{}, 0)
	for k, v := range g.Properties {
		copiedMap[k] = v
	}
	copiedMap["id"] = g.ID

	if mapAsJSON, err := json.Marshal(copiedMap); err != nil {
		return err
	} else {
		return json.Unmarshal(mapAsJSON, target)
	}
}
