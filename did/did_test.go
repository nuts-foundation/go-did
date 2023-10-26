package did

import (
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/require"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDID_UnmarshalJSON(t *testing.T) {
	jsonTestSting := `"did:nuts:123"`

	id := DID{}
	err := json.Unmarshal([]byte(jsonTestSting), &id)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	if id.Method != "nuts" {
		t.Errorf("expected nuts got %s", id.Method)
		return
	}
}

func TestDID_MarshalJSON(t *testing.T) {
	actual, err := json.Marshal(MustParseDID("did:nuts:123"))
	require.NoError(t, err)
	assert.Equal(t, `"did:nuts:123"`, string(actual))
}

func TestParseDID(t *testing.T) {
	t.Run("parse a DID", func(t *testing.T) {
		id, err := ParseDID("did:nuts:123")
		require.NoError(t, err)
		assert.Equal(t, "did:nuts:123", id.String())
		assert.Equal(t, "nuts", id.Method)
		assert.Equal(t, "123", id.ID)
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		id, err := ParseDID("invalidDID")
		assert.Nil(t, id)
		assert.ErrorIs(t, err, ErrInvalidDID)
	})
	t.Run("error - is empty", func(t *testing.T) {
		id, err := ParseDID("")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID: DID must start with 'did:'")
	})
	t.Run("error - is a DID URL, without DID", func(t *testing.T) {
		id, err := ParseDID("#fragment")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID: DID must start with 'did:'")
	})
	t.Run("error - is a DID URL", func(t *testing.T) {
		id, err := ParseDID("did:example:123/foo")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID: DID can not have path, fragment or query params")
	})
}

func TestMustParseDID(t *testing.T) {
	assert.Panics(t, func() {
		MustParseDID("did:nuts:123/path?query#fragment")
	})
}

func TestDID_MarshalText(t *testing.T) {
	expected := "did:nuts:123"
	id, _ := ParseDID(expected)
	actual, err := id.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestDID_Equal(t *testing.T) {
	const did = "did:example:123"
	t.Run("equal", func(t *testing.T) {
		assert.True(t, MustParseDID(did).Equals(MustParseDID(did)))
	})
	t.Run("method differs", func(t *testing.T) {
		assert.False(t, MustParseDID("did:example1:123").Equals(MustParseDID(did)))
	})
	t.Run("ID differs", func(t *testing.T) {
		assert.False(t, MustParseDID("did:example:1234").Equals(MustParseDID(did)))
	})
	t.Run("one DID is empty", func(t *testing.T) {
		assert.False(t, MustParseDID("did:example:1234").Equals(DID{}))
	})
	t.Run("both DIDs are empty", func(t *testing.T) {
		assert.True(t, DID{}.Equals(DID{}))
	})
}

func TestDID_String(t *testing.T) {
	type testCase struct {
		name     string
		expected string
		did      DID
	}
	testCases := []testCase{
		{
			name:     "basic DID",
			expected: "did:example:123",
			did: DID{
				Method: "example",
				ID:     "123",
			},
		},
		{
			name:     "empty DID",
			expected: "",
			did:      DID{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.did.String())
		})
	}
}

func TestDID_Empty(t *testing.T) {
	t.Run("DID", func(t *testing.T) {
		assert.False(t, MustParseDID("did:nuts:123").Empty())
	})
	t.Run("empty when just generated", func(t *testing.T) {
		id := DID{}
		assert.True(t, id.Empty())
	})
}

func TestDID_URI(t *testing.T) {
	id, err := ParseDID("did:nuts:123")

	if !assert.NoError(t, err) {
		return
	}

	uri := id.URI()

	assert.Equal(t, id.String(), uri.String())
}

func TestError(t *testing.T) {
	actual := ErrInvalidDID.wrap(io.EOF)
	assert.True(t, errors.Is(actual, ErrInvalidDID))
	assert.True(t, errors.Is(actual, io.EOF))
	assert.False(t, errors.Is(actual, io.ErrShortBuffer))
}
