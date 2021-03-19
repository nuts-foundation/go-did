package vc

import (
	"github.com/nuts-foundation/go-did/internal/marshal"
)

const contextKey = "@context"
const credentialSubjectKey = "credentialSubject"
const proofKey = "proof"

var pluralContext = marshal.Plural(contextKey)
