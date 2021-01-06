package didparser

import (
	"encoding/json"
	"fmt"
	"net/url"
)


// singleOrArray can unmarshal json strings values into an array. Used to normalize a document.
type singleOrArray []interface{}

func (s *singleOrArray) UnmarshalJSON(b []byte) (err error) {
	if b[0] == '[' {
		// use an alias to prevent infinite loop by calling UnmarshalJSON
		type Alias singleOrArray
		arrayResult := Alias{}
		err = json.Unmarshal(b, &arrayResult)
		*s = singleOrArray(arrayResult)
	} else {
		var singleResult interface{}
		err = json.Unmarshal(b, &singleResult)
		*s = singleOrArray{singleResult}
	}
	return
}

// URI is a wrapper around url.URL to add json marshalling
type URI struct {
	url.URL
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