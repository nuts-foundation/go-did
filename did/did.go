package did

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"net/url"
	"strings"
)

var _ fmt.Stringer = DID{}
var _ encoding.TextMarshaler = DID{}

// DIDContextV1 contains the JSON-LD context for a DID Document
const DIDContextV1 = "https://www.w3.org/ns/did/v1"

// DIDContextV1URI returns DIDContextV1 as a URI
func DIDContextV1URI() ssi.URI {
	return ssi.MustParseURI(DIDContextV1)
}

// DID represent a Decentralized Identifier as specified by the DID Core specification (https://www.w3.org/TR/did-core/#identifier).
type DID struct {
	// Method is the DID method, e.g. "example".
	Method string
	// ID is the method-specific ID, in escaped form.
	ID string
	// DecodedID is the method-specific ID, in unescaped form.
	// It is only set during parsing, and not used by the String() method.
	DecodedID string
}

// Empty checks whether the DID is set or not
func (d DID) Empty() bool {
	return d.Method == ""
}

// String returns the DID as formatted string.
func (d DID) String() string {
	if d.Empty() {
		return ""
	}
	var result string
	if d.Method != "" {
		result += "did:" + d.Method + ":" + d.ID
	}
	return result
}

// MarshalText implements encoding.TextMarshaler
func (d DID) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// Equals checks whether the DID equals to another DID.
// The check is case-sensitive.
func (d DID) Equals(other DID) bool {
	return d.String() == other.String()
}

// UnmarshalJSON unmarshals a DID encoded as JSON string, e.g.:
// "did:nuts:c0dc584345da8a0e1e7a584aa4a36c30ebdb79d907aff96fe0e90ee972f58a17"
func (d *DID) UnmarshalJSON(bytes []byte) error {
	var didString string
	err := json.Unmarshal(bytes, &didString)
	if err != nil {
		return ErrInvalidDID.wrap(err)
	}
	tmp, err := ParseDID(didString)
	if err != nil {
		return err
	}
	*d = *tmp
	return nil
}

// MarshalJSON marshals the DID to a JSON string
func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// URI converts the DID to a URI.
// URIs are used in Verifiable Credentials
func (d DID) URI() ssi.URI {
	return ssi.URI{
		URL: url.URL{
			Scheme: "did",
			Opaque: fmt.Sprintf("%s:%s", d.Method, d.ID),
		},
	}
}

// ParseDID parses a raw DID.
// If the input contains a path, query or fragment, use the ParseDIDURL instead.
// If it can't be parsed, an error is returned.
func ParseDID(input string) (*DID, error) {
	didURL, err := ParseDIDURL(input)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(didURL.String(), "did:") {
		return nil, ErrInvalidDID.wrap(errors.New("DID must start with 'did:'"))
	}
	if !didURL.urlEmpty() {
		return nil, ErrInvalidDID.wrap(errors.New("DID can not have path, fragment or query params"))
	}
	return &didURL.DID, nil
}

// MustParseDID is like ParseDID but panics if the string cannot be parsed.
// It simplifies safe initialization of global variables holding compiled UUIDs.
func MustParseDID(input string) DID {
	result, err := ParseDID(input)
	if err != nil {
		panic(err)
	}
	return *result
}

// ErrInvalidDID is returned when a parser function is supplied with a string that can't be parsed as DID.
var ErrInvalidDID = ParserError{msg: "invalid DID"}

// ParserError is used when returning DID-parsing related errors.
type ParserError struct {
	msg string
	err error
}

func (w ParserError) wrap(err error) error {
	return ParserError{msg: fmt.Sprintf("%s: %s", w.msg, err.Error()), err: err}
}

// Is checks whether the given error is a ParserError
func (w ParserError) Is(other error) bool {
	_, ok := other.(ParserError)
	return ok
}

// Unwrap returns the underlying error.
func (w ParserError) Unwrap() error {
	return w.err
}

// Error returns the message of the error.
func (w ParserError) Error() string {
	return w.msg
}
