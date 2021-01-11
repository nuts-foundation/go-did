package marshaling

import "encoding/json"

// SingleOrArray can unmarshal json strings values into an array. Used to normalize a document.
type SingleOrArray []interface{}

func (s *SingleOrArray) UnmarshalJSON(b []byte) (err error) {
	if b[0] == '[' {
		// use an alias to prevent infinite loop by calling UnmarshalJSON
		type Alias SingleOrArray
		arrayResult := Alias{}
		err = json.Unmarshal(b, &arrayResult)
		*s = SingleOrArray(arrayResult)
	} else {
		var singleResult interface{}
		err = json.Unmarshal(b, &singleResult)
		*s = SingleOrArray{singleResult}
	}
	return
}

// NormalizeDocument accepts a JSON document and converts all singular values (string/numeric/bool/object)
// of the keys that are present in `pluralKeys` to an array. This makes unmarshalling DID Documents or Verifiable Credentials
// easier, since those formats allow certain properties to be either a singular value or an array of values.
//
// Example input: 												{"message": "Hello, World"}
// Example output (if 'message' is supplied in 'pluralKeys'): 	{"message": ["Hello, World"]}
//
// This function does not support nested keys.
func NormalizeDocument(document []byte, pluralKeys ...string) ([]byte, error) {
	tmp := make(map[string]interface{}, 0)
	if err := json.Unmarshal(document, &tmp); err != nil {
		return nil, err
	}
	for _, key := range pluralKeys {
		if _, isSlice := tmp[key].([]interface{}); tmp[key] != nil && !isSlice {
			tmp[key] = []interface{}{tmp[key]}
		}
	}
	return json.Marshal(tmp)
}
