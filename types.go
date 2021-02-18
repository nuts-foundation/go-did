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

func (v URI) String() string {
	return v.URL.String()
}