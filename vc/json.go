package vc

import (
	"github.com/nuts-foundation/go-did/internal/marshal"
)

const (
	contextKey              = "@context"
	typeKey                 = "type"
	credentialSubjectKey    = "credentialSubject"
	credentialStatusKey     = "credentialStatus"
	proofKey                = "proof"
	verifiableCredentialKey = "verifiableCredential"
)

var pluralContext = marshal.Plural(contextKey)
