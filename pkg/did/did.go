package did

import (
	"encoding/json"
	"fmt"

	ockamDid "github.com/ockam-network/did"
)

// DID represents a Decentralized Identifier as specified by the DID Core specification (https://www.w3.org/TR/did-core/#identifier).
type DID struct {
	ockamDid.DID
}

// Empty returns whether the DID is empty or not
func (d DID) Empty() bool {
	return d.ID == ""
}

// Equals checks whether the DID is exactly equal to another DID
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

// ParseDID parses a raw DID. If it can't be parsed, an error is returned.
func ParseDID(input string) (*DID, error) {
	ockDid, err := ockamDid.Parse(input)
	if err != nil {
		return nil, err
	}

	return &DID{DID: *ockDid}, nil
}

