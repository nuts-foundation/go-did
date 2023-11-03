package did

import (
	"encoding"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"net/url"
	"regexp"
	"strings"
)

var _ fmt.Stringer = DIDURL{}
var _ encoding.TextMarshaler = DIDURL{}

var didURLPattern = regexp.MustCompile(`^(did:([a-z0-9]+):((?:(?:[a-zA-Z0-9.\-_:])+|(?:%[0-9a-fA-F]{2})+)+)|)(/.*?|)(\?.*?|)(#.*|)$`)

type DIDURL struct {
	DID

	// Path is the DID path without the leading '/', in escaped form.
	Path string
	// DecodedPath is the DID path without the leading '/', in unescaped form.
	// It is only set during parsing, and not used by the String() method.
	DecodedPath string
	// Query contains the DID query key-value pairs, in unescaped form.
	// String() will escape the values again, and order the keys alphabetically.
	Query url.Values
	// Fragment is the DID fragment without the leading '#', in escaped form.
	Fragment string
	// DecodedFragment is the DID fragment without the leading '#', in unescaped form.
	// It is only set during parsing, and not used by the String() method.
	DecodedFragment string
}

// Equals checks whether the DIDURL equals to another DIDURL.
// The check is case-sensitive.
func (d DIDURL) Equals(other DIDURL) bool {
	return d.cleanup().String() == other.cleanup().String()
}

// UnmarshalJSON unmarshals a DID URL encoded as JSON string, e.g.:
// "did:nuts:c0dc584345da8a0e1e7a584aa4a36c30ebdb79d907aff96fe0e90ee972f58a17#key-1"
func (d *DIDURL) UnmarshalJSON(bytes []byte) error {
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

// MarshalJSON marshals the DIDURL to a JSON string
func (d DIDURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// Empty checks whether the DID is set or not
func (d DIDURL) Empty() bool {
	return d.DID.Empty() && d.urlEmpty()
}

// urlEmpty checks whether the URL part of the DID URL is set or not (path, fragment, or query).
func (d DIDURL) urlEmpty() bool {
	return d.Path == "" && d.Fragment == "" && len(d.Query) == 0
}

// String returns the DID as formatted string.
func (d DIDURL) String() string {
	if d.Empty() {
		return ""
	}
	result := d.DID.String()
	if d.Path != "" {
		result += "/" + d.Path
	}
	if len(d.Query) > 0 {
		result += "?" + d.Query.Encode()
	}
	if d.Fragment != "" {
		result += "#" + d.Fragment
	}
	return result
}

func (d DIDURL) cleanup() DIDURL {
	if len(d.Query) == 0 {
		d.Query = nil
	}
	return d
}

// URI converts the DIDURL to a URI.
// URIs are used in Verifiable Credentials
func (d DIDURL) URI() ssi.URI {
	var result ssi.URI
	if !d.DID.Empty() {
		result = d.DID.URI()
	}
	if d.Path != "" {
		result.Opaque += "/" + d.Path
	}
	if len(d.Query) != 0 {
		result.Opaque += "?" + d.Query.Encode()
	}
	result.Fragment = d.Fragment
	return result
}

// ParseDIDURL parses a DID URL.
// https://www.w3.org/TR/did-core/#did-url-syntax
// A DID URL is a URL that builds on the DID scheme.
func ParseDIDURL(input string) (*DIDURL, error) {
	// There are 6 submatches (base 0)
	// 0. DID + path + query + fragment
	// 1. DID
	// 2. method
	// 3. id
	// 4. path (starting with '/')
	// 5. query (starting with '?')
	// 6. fragment (starting with '#')
	matches := didURLPattern.FindStringSubmatch(input)
	if len(matches) == 0 {
		return nil, ErrInvalidDID
	}

	result := DIDURL{
		DID: DID{
			Method: matches[2],
			ID:     matches[3],
		},
		Path:     strings.TrimPrefix(matches[4], "/"),
		Fragment: strings.TrimPrefix(matches[6], "#"),
	}
	var err error
	result.DecodedID, err = url.PathUnescape(result.ID)
	if err != nil {
		return nil, ErrInvalidDID.wrap(fmt.Errorf("invalid ID: %w", err))
	}
	result.DecodedPath, err = url.PathUnescape(result.Path)
	if err != nil {
		return nil, ErrInvalidDID.wrap(fmt.Errorf("invalid path: %w", err))
	}
	result.DecodedFragment, err = url.PathUnescape(result.Fragment)
	if err != nil {
		return nil, ErrInvalidDID.wrap(fmt.Errorf("invalid fragment: %w", err))
	}
	result.Query, err = url.ParseQuery(strings.TrimPrefix(matches[5], "?"))
	if err != nil {
		return nil, ErrInvalidDID.wrap(err)
	}
	result = result.cleanup()
	return &result, nil
}

// MustParseDIDURL is like ParseDIDURL but panics if the string cannot be parsed.
// It simplifies safe initialization of global variables holding compiled UUIDs.
func MustParseDIDURL(input string) DIDURL {
	result, err := ParseDIDURL(input)
	if err != nil {
		panic(err)
	}
	return *result
}
