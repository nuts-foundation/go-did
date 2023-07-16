package did

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nuts-foundation/go-did"
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
	url.URL
	Method string
	ID     string
	Path   string
	raw    string
}

// Empty checks whether the DID is set or not
func (d DID) Empty() bool {
	return d.Method == ""
}

// String returns the DID as formatted string.
func (d DID) String() string {
	return d.raw
}

// MarshalText implements encoding.TextMarshaler
func (d DID) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
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
		return ErrInvalidDID.wrap(err)
	}
	tmp, err := ParseDIDURL(didString)
	if err != nil {
		return err
	}
	*d = *tmp
	return nil
}

func (d *DID) IsURL() bool {
	return d.Fragment != "" || d.RawQuery != "" || d.Path != ""
}

// MarshalJSON marshals the DID to a JSON string
func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
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

// WithoutURL returns a copy of the DID without URL parts (fragment, query, path).
func (d DID) WithoutURL() DID {
	u := d.URL
	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = ""
	u.Path = ""
	u.RawPath = ""
	return DID{
		Method: d.Method,
		ID:     d.ID,
		raw:    "did:" + d.Method + ":" + d.ID,
		URL:    u,
	}
}

// ParseDIDURL parses a DID URL.
// https://www.w3.org/TR/did-core/#did-url-syntax
// A DID URL is a URL that builds on the DID scheme.
func ParseDIDURL(input string) (*DID, error) {
	withoutScheme := strings.TrimPrefix(input, "did:")
	if len(withoutScheme) == len(input) {
		return nil, ErrInvalidDID.wrap(errors.New("input does not begin with 'did:' prefix"))
	}
	parsedURL, err := url.Parse(withoutScheme)
	if err != nil {
		return nil, ErrInvalidDID.wrap(err)
	}
	if parsedURL.Scheme == "" {
		return nil, ErrInvalidDID
	}
	// Since DIDs are opaque URIs, we need to parse the path part ourselves.
	pathIdx := strings.Index(parsedURL.Opaque, "/")
	id := parsedURL.Opaque
	path := parsedURL.RawPath
	if pathIdx != -1 {
		id = parsedURL.Opaque[:pathIdx]
		path = parsedURL.Opaque[pathIdx+1:]
	}

	return &DID{
		Method: parsedURL.Scheme,
		ID:     id,
		Path:   path,
		raw:    input,
		URL:    *parsedURL,
	}, nil
}

// ParseDID parses a raw DID.
// If the input contains a path, query or fragment, use the ParseDIDURL instead.
// If it can't be parsed, an error is returned.
func ParseDID(input string) (*DID, error) {
	did, err := ParseDIDURL(input)
	if err != nil {
		return nil, err
	}
	if did.IsURL() {
		return nil, ErrInvalidDID.wrap(errors.New("DID can not have path, fragment or query params"))
	}
	return did, nil
}

// must accepts a function like Parse and returns the value without error or panics otherwise.
func must(fn func(string) (*DID, error), input string) DID {
	v, err := fn(input)
	if err != nil {
		panic(err)
	}
	return *v
}

// MustParseDID is like ParseDID but panics if the string cannot be parsed.
// It simplifies safe initialization of global variables holding compiled UUIDs.
func MustParseDID(input string) DID {
	return must(ParseDID, input)
}

// MustParseDIDURL is like ParseDIDURL but panics if the string cannot be parsed.
// It simplifies safe initialization of global variables holding compiled UUIDs.
func MustParseDIDURL(input string) DID {
	return must(ParseDIDURL, input)
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
