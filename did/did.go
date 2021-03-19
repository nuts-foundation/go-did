package did

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"net/url"

	ockamDid "github.com/ockam-network/did"
)

const DIDContextV1 = "https://www.w3.org/ns/did/v1"

func DIDContextV1URI() ssi.URI {
	if underlyingURL, err := ssi.ParseURI(DIDContextV1); err != nil {
		panic(err)
	} else {
		return *underlyingURL
	}
}

// DID represents a Decentralized Identifier as specified by the DID Core specification (https://www.w3.org/TR/did-core/#identifier).
type DID struct {
	ockamDid.DID
}

// Empty checks whether the DID is set or not
func (d DID) Empty() bool {
	return d.Method == ""
}

// String returns the DID as formatted string.
func (d DID) String() string {
	return d.DID.String()
}

// Equals checks whether the DID is exactly equal to another DID
// The check is case sensitive.
func (d DID) Equals(other DID) bool {
	return d.String() == other.String()
}

// UnmarshalJSON unmarshals a DID encoded as JSON string, e.g.:
// "did:nuts:c0dc584345da8a0e1e7a584aa4a36c30ebdb79d907aff96fe0e90ee972f58a17"
func (d *DID) UnmarshalJSON(bytes []byte) error {
	var didString string
	err := json.Unmarshal(bytes, &didString)
	if err != nil {
		return fmt.Errorf("unable to unmarshal DID: %w", err)
	}
	tmp, err := ockamDid.Parse(didString)
	if err != nil {
		return fmt.Errorf("unable to parse did: %w", err)
	}
	d.DID = *tmp
	return nil
}

// MarshalJSON marshals the DID to a JSON string
func (d DID) MarshalJSON() ([]byte, error) {
	didAsString := d.DID.String()
	return json.Marshal(didAsString)
}

// URI converts the DID to an URI.
// URIs are used in Verifiable Credentials
func (d DID) URI() ssi.URI {
	return ssi.URI{
		URL: url.URL{
			Scheme:   "did",
			Opaque:   fmt.Sprintf("%s:%s", d.Method, d.ID),
			Fragment: d.Fragment,
		},
	}
}

// ParseDID parses a raw DID. If it can't be parsed, an error is returned.
func ParseDID(input string) (*DID, error) {
	ockDid, err := ockamDid.Parse(input)
	if err != nil {
		return nil, err
	}

	return &DID{DID: *ockDid}, nil
}
