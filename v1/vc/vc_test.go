package vc

import (
	"github.com/nuts-foundation/go-did/v1/ld"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	data, err := os.ReadFile("test/example7.json")
	require.NoError(t, err)

	actual, err := Parse(string(data), ld.Loader())

	require.NoError(t, err)
	require.NotNil(t, actual)

	// ID
	ok, id := actual.ID()
	require.True(t, ok)
	require.Equal(t, "http://example.edu/credentials/3732", id.ID().String())
	// IssuanceDate
	require.Equal(t, "2010-01-01 00:00:00 +0000 UTC", actual.IssuanceDate().String())
	// Type
	require.Len(t, actual.Type(), 2)
	require.Contains(t, actual.Type(), "https://www.w3.org/2018/credentials#VerifiableCredential")
	require.Contains(t, actual.Type(), "https://example.org/examples#RelationshipCredential")
	// Context
	require.Len(t, actual.Context(), 2)
	require.Equal(t, "https://www.w3.org/2018/credentials/v1", actual.Context()[0])
	require.Equal(t, "https://www.w3.org/2018/credentials/examples/v1", actual.Context()[1])
	// CredentialSubject
	subjects := actual.CredentialSubject()
	require.Len(t, subjects, 2)
	{
		subject := subjects[0]
		ok, id := subject.ID()
		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", id.String())
		subject.Get()
	}

}
