package did

import (
	"encoding/json"
	"errors"
	"fmt"
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
		t.Run("did:nuts", func(t *testing.T) {
			id, err := ParseDID("did:nuts:123")
			require.NoError(t, err)
			assert.Equal(t, "did:nuts:123", id.String())
			assert.Equal(t, "nuts", id.Method)
			assert.Equal(t, "123", id.ID)
		})
		t.Run("fragment", func(t *testing.T) {
			id, err := ParseDIDURL("did:example:123#fragment")
			require.NoError(t, err)
			assert.Equal(t, "did:example:123#fragment", id.String())
			assert.Equal(t, "fragment", id.Fragment)
		})
		t.Run("path", func(t *testing.T) {
			id, err := ParseDIDURL("did:example:123/subpath")
			require.NoError(t, err)
			assert.Equal(t, "123", id.ID)
			assert.Equal(t, "subpath", id.Path)
		})
		t.Run("empty path", func(t *testing.T) {
			id, err := ParseDIDURL("did:example:123/")
			require.NoError(t, err)
			assert.Equal(t, "123", id.ID)
			assert.Equal(t, "", id.Path)
		})
		t.Run("path and query", func(t *testing.T) {
			id, err := ParseDIDURL("did:example:123/subpath?param=value")
			require.NoError(t, err)
			assert.Equal(t, "123", id.ID)
			assert.Equal(t, "subpath", id.Path)
			assert.Len(t, id.Query, 1)
			assert.Equal(t, "value", id.Query.Get("param"))
		})
		t.Run("did:web", func(t *testing.T) {
			t.Run("root without port", func(t *testing.T) {
				id, err := ParseDID("did:web:example.com")
				require.NoError(t, err)
				assert.Equal(t, "did:web:example.com", id.String())
			})
			t.Run("root with port", func(t *testing.T) {
				id, err := ParseDID("did:web:example.com%3A3000")
				require.NoError(t, err)
				assert.Equal(t, "did:web:example.com%3A3000", id.String())
			})
			t.Run("subpath", func(t *testing.T) {
				id, err := ParseDID("did:web:example.com%3A3000:user:alice")
				require.NoError(t, err)
				assert.Equal(t, "did:web:example.com%3A3000:user:alice", id.String())
				assert.Equal(t, "web", id.Method)
				assert.Equal(t, "example.com%3A3000:user:alice", id.ID)
			})
			t.Run("path, query and fragment", func(t *testing.T) {
				id, err := ParseDIDURL("did:web:example.com%3A3000:user:alice/foo/bar?param=value#fragment")
				require.NoError(t, err)
				assert.Equal(t, "did:web:example.com%3A3000:user:alice/foo/bar?param=value#fragment", id.String())
				assert.Equal(t, "web", id.Method)
				assert.Equal(t, "example.com%3A3000:user:alice", id.ID)
				assert.Equal(t, "foo/bar", id.Path)
				assert.Len(t, id.Query, 1)
				assert.Equal(t, "value", id.Query.Get("param"))
				assert.Equal(t, "fragment", id.Fragment)
			})
		})
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		id, err := ParseDID("invalidDID")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID: input does not begin with 'did:' prefix")
	})
	t.Run("error - no method", func(t *testing.T) {
		id, err := ParseDID("did:")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID")
	})
	t.Run("error - no method, but with path", func(t *testing.T) {
		id, err := ParseDID("did:/foo")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID")
	})
	t.Run("error - DID URL", func(t *testing.T) {
		id, err := ParseDID("did:nuts:123/path?query#fragment")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID: DID can not have path, fragment or query params")
	})
}

func TestMustParseDID(t *testing.T) {
	assert.Panics(t, func() {
		MustParseDID("did:nuts:123/path?query#fragment")
	})
}

func TestParseDIDURL(t *testing.T) {
	t.Run("ok parse a DID", func(t *testing.T) {
		id, err := ParseDIDURL("did:nuts:123")

		if err != nil {
			t.Errorf("unexpected error: %s", err)
			return
		}

		if id.String() != "did:nuts:123" {
			t.Errorf("expected parsed did to be 'did:nuts:123', got: %s", id.String())
		}
	})

	t.Run("ok - parse a DID URL", func(t *testing.T) {
		id, err := ParseDIDURL("did:nuts:123/path?query#fragment")
		assert.Equal(t, "did:nuts:123/path?query=#fragment", id.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid DID", func(t *testing.T) {
		id, err := ParseDIDURL("invalidDID")
		assert.Nil(t, id)
		assert.EqualError(t, err, "invalid DID: input does not begin with 'did:' prefix")

	})
}

func TestMustParseDIDURL(t *testing.T) {
	assert.Panics(t, func() {
		MustParseDIDURL("invalidDID")
	})
}

func TestDID_String(t *testing.T) {
	expected := "did:nuts:123"
	id, _ := ParseDID(expected)
	assert.Equal(t, expected, fmt.Sprintf("%s", *id))
}

func TestDID_MarshalText(t *testing.T) {
	expected := "did:nuts:123"
	id, _ := ParseDID(expected)
	actual, err := id.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestDID_Empty(t *testing.T) {
	t.Run("not empty for filled did", func(t *testing.T) {
		id, err := ParseDID("did:nuts:123")
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			return
		}
		assert.False(t, id.Empty())
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

func TestDID_WithoutURL(t *testing.T) {
	id := MustParseDIDURL("did:example:123/path?key=value#fragment").WithoutURL()
	assert.Equal(t, "did:example:123", id.String())
	assert.Empty(t, id.Path)
	assert.Empty(t, id.Fragment)
	assert.Empty(t, id.Query)
}
