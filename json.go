package did

import (
	"github.com/nuts-foundation/go-did/internal/marshal"
)

const contextKey = "@context"
const controllerKey = "controller"
const authenticationKey = "authentication"
const verificationMethodKey = "verificationMethod"
const assertionMethodKey = "assertionMethod"
const serviceEndpointKey = "serviceEndpoint"
const credentialSubjectKey = "credentialSubject"
const proofKey = "proof"

var pluralContext = marshal.Plural(contextKey)
