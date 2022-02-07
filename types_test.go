package ssi

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseURI(t *testing.T) {

	t.Run("for VC types", func(t *testing.T) {
		u, err := ParseURI("SomeType")

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "SomeType", u.String())
	})

	t.Run("for URI types", func(t *testing.T) {
		u, err := ParseURI("https://example.com/context/v1")

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "https://example.com/context/v1", u.String())
	})

	t.Run("malformed input", func(t *testing.T) {
		_, err := ParseURI(string([]byte{0}))

		assert.Error(t, err)
	})
}

func TestMustParseURI(t *testing.T) {
	assert.Panics(t, func() {
		MustParseURI(string([]byte{0}))
	})
}

func TestURI_String(t *testing.T) {
	assert.Equal(t, "http://test", URI{url.URL{Scheme: "http", Host: "test"}}.String())
}

func TestURI_MarshalText(t *testing.T) {
	actual, err := URI{url.URL{Scheme: "http", Host: "test"}}.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte("http://test"), actual)
}
