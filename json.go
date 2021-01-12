package did

import (
	"errors"
	"github.com/nuts-foundation/did/internal"
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

var standardAliases internal.Normalizer = func(m map[string]interface{}) {
	internal.KeyAlias("@context", contextKey)(m)
	internal.KeyAlias("@id", idKey)(m)
}
var pluralContext = internal.Plural(contextKey)

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
