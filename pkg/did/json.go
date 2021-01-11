package did

import (
	"errors"
	"github.com/nuts-foundation/did/marshal"
	"net/url"
)

const contextKey = "context"
const idKey = "id"
const controllerKey = "controller"
const authenticationKey = "authentication"
const verificationMethodKey = "verificationMethod"
const assertionMethodKey = "assertionMethod"
const serviceKey = "service"
const typeKey = "type"
const serviceEndpointKey = "serviceEndpoint"

var standardAliases = []marshal.Normalizer{
	marshal.KeyAlias("@context", contextKey),
	marshal.KeyAlias("@id", idKey),
}
var pluralContext = marshal.Plural(contextKey)

func parseURLs(input []interface{}) ([]url.URL, error) {
	result := make([]url.URL, len(input))
	for i := 0; i < len(input); i++ {
		if asString, ok := input[i].(string); !ok {
			return nil, errors.New("not a string")
		} else if u, err := url.Parse(asString); err != nil {
			return nil, err
		} else {
			result[i] = *u
		}
	}
	return result, nil
}
