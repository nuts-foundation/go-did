package did

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// URI is a wrapper around url.URL to add json marshalling
type URI struct {
	url.URL
}

func (v URI) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v *URI) UnmarshalJSON(bytes []byte) error {
	var value string
	if err := json.Unmarshal(bytes, &value); err != nil {
		return err
	}
	parsedUrl, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("could not parse URI: %w", err)
	}
	v.URL = *parsedUrl
	return nil
}

// ParseURI parses a raw URI. If it can't be parsed, an error is returned.
func ParseURI(input string) (*URI, error) {
	u, err := url.Parse(input)
	if err != nil {
		return nil, err
	}

	return &URI{URL: *u}, nil
}
