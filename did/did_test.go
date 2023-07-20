package did

import (
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/require"
	"io"
	"net/url"
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
	t.Run("error - input is a DID URL", func(t *testing.T) {
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
	t.Run("parse a DID URL", func(t *testing.T) {
		id, err := ParseDIDURL("did:nuts:123/path?query#fragment")
		assert.Equal(t, "did:nuts:123/path?query=#fragment", id.String())
		assert.NoError(t, err)
	})
	t.Run("with fragment", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:123#fragment")
		require.NoError(t, err)
		assert.Equal(t, "did:example:123#fragment", id.String())
		assert.Equal(t, "fragment", id.Fragment)
	})
	t.Run("with path", func(t *testing.T) {
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
			assert.Equal(t, "did:web:example.com:3000", id.String())
		})
		t.Run("subpath", func(t *testing.T) {
			id, err := ParseDID("did:web:example.com%3A3000:user:alice")
			require.NoError(t, err)
			assert.Equal(t, "did:web:example.com:3000:user:alice", id.String())
			assert.Equal(t, "web", id.Method)
			assert.Equal(t, "example.com:3000:user:alice", id.ID)
		})
		t.Run("subpath without port", func(t *testing.T) {
			id, err := ParseDID("did:web:example.com:u:5")
			require.NoError(t, err)
			assert.Equal(t, "did:web:example.com:u:5", id.String())
			assert.Equal(t, "web", id.Method)
			assert.Equal(t, "example.com:u:5", id.ID)
		})
		t.Run("path, query and fragment", func(t *testing.T) {
			id, err := ParseDIDURL("did:web:example.com%3A3000:user:alice/foo/bar?param=value#fragment")
			require.NoError(t, err)
			assert.Equal(t, "did:web:example.com:3000:user:alice/foo/bar?param=value#fragment", id.String())
			assert.Equal(t, "web", id.Method)
			assert.Equal(t, "example.com:3000:user:alice", id.ID)
			assert.Equal(t, "foo/bar", id.Path)
			assert.Len(t, id.Query, 1)
			assert.Equal(t, "value", id.Query.Get("param"))
			assert.Equal(t, "fragment", id.Fragment)
		})
	})

	t.Run("ok - parsed DID URL equals constructed one", func(t *testing.T) {
		parsed, err := ParseDIDURL("did:nuts:123/path?key=value#fragment")
		require.NoError(t, err)
		constructed := DID{
			Method: "nuts",
			ID:     "123",
			Path:   "path",
			Query: url.Values{
				"key": []string{"value"},
			},
			Fragment: "fragment",
		}
		assert.Equal(t, constructed, *parsed)
	})
	t.Run("ok - parsed DID URL equals constructed one (no query)", func(t *testing.T) {
		parsed, err := ParseDIDURL("did:nuts:123/path#fragment")
		require.NoError(t, err)
		constructed := DID{
			Method:   "nuts",
			ID:       "123",
			Path:     "path",
			Fragment: "fragment",
		}
		assert.Equal(t, constructed, *parsed)
	})

	t.Run("percent-encoded characters in ID are allowed", func(t *testing.T) {
		parsed, err := ParseDIDURL("did:example:123%f8")
		require.NoError(t, err)
		constructed := DID{
			Method: "example",
			ID:     "123%F8",
		}
		assert.Equal(t, constructed, *parsed)
	})

	t.Run("format validation", func(t *testing.T) {
		type testCase struct {
			name string
			did  string
		}
		t.Run("valid DIDs", func(t *testing.T) {
			testCases := []testCase{
				{name: "basic DID", did: "did:example:123"},
				{name: "with query", did: "did:example:123?foo=bar"},
				{name: "with fragment", did: "did:example:123#foo"},
				{name: "with path", did: "did:example:123/foo"},
				{name: "with query, fragment and path", did: "did:example:123/foo?key=value#fragment"},
				{name: "with semicolons", did: "did:example:123/foo?key=value#fragment"},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					id, err := ParseDIDURL(tc.did)
					assert.NoError(t, err, "expected no error for DID: "+tc.did)
					assert.Equal(t, tc.did, id.String())
				})
			}
		})
		t.Run("invalid DIDs", func(t *testing.T) {
			testCases := []testCase{
				{
					name: "no method",
					did:  "did:",
				},
				{
					name: "does not begin with 'did:' prefix",
					did:  "example:123",
				},
				{
					name: "method contains invalid character",
					did:  "did:example_:1234",
				},
				{
					name: "ID is empty",
					did:  "did:example:",
				},
				{
					name: "ID is empty, with path",
					did:  "did:example:/path",
				},
				{
					name: "ID is empty, with fragment",
					did:  "did:example:#fragment",
				},
				{
					name: "ID contains invalid chars",
					did:  "did:example:te@st",
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					id, err := ParseDIDURL(tc.did)
					assert.Error(t, err, "expected an error for DID: "+tc.did)
					assert.Nil(t, id)
				})
			}
		})
	})
}

func TestMustParseDIDURL(t *testing.T) {
	assert.Panics(t, func() {
		MustParseDIDURL("invalidDID")
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
	t.Run("DID", func(t *testing.T) {
		t.Run("equal", func(t *testing.T) {
			assert.True(t, MustParseDID("did:example:123").Equals(MustParseDID("did:example:123")))
		})
		t.Run("method differs", func(t *testing.T) {
			assert.False(t, MustParseDID("did:example1:123").Equals(MustParseDID("did:example:123")))
		})
		t.Run("ID differs", func(t *testing.T) {
			assert.False(t, MustParseDID("did:example:1234").Equals(MustParseDID("did:example:123")))
		})
		t.Run("one DID is empty", func(t *testing.T) {
			assert.False(t, MustParseDID("did:example:1234").Equals(DID{}))
		})
		t.Run("both DIDs are empty", func(t *testing.T) {
			assert.True(t, DID{}.Equals(DID{}))
		})
	})
	t.Run("DID URL", func(t *testing.T) {
		t.Run("equal", func(t *testing.T) {
			d1 := MustParseDIDURL("did:example:123/foo?key=value#fragment")
			d2 := MustParseDIDURL("did:example:123/foo?key=value#fragment")
			assert.True(t, d1.Equals(d2))
		})
		t.Run("fragment differs", func(t *testing.T) {
			d1 := MustParseDIDURL("did:example:123/foo?key=value")
			d2 := MustParseDIDURL("did:example:123/foo?key=value#fragment")
			assert.False(t, d1.Equals(d2))
		})
		t.Run("query in different order", func(t *testing.T) {
			d1 := MustParseDIDURL("did:example:123/foo?k1=a&k2=b")
			d2 := MustParseDIDURL("did:example:123/foo?k2=b&k1=a")
			assert.True(t, d1.Equals(d2))
		})
		t.Run("path differs", func(t *testing.T) {
			d1 := MustParseDIDURL("did:example:123/fuzz?key=value#fragment")
			d2 := MustParseDIDURL("did:example:123/fizz?key=value#fragment")
			assert.False(t, d1.Equals(d2))
		})
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
			name:     "with path",
			expected: "did:example:123/foo",
			did: DID{
				Method: "example",
				ID:     "123",
				Path:   "foo",
			},
		},
		{
			name:     "with fragment",
			expected: "did:example:123#fragment",
			did: DID{
				Method:   "example",
				ID:       "123",
				Fragment: "fragment",
			},
		},
		{
			name:     "with query",
			expected: "did:example:123?key=value",
			did: DID{
				Method: "example",
				ID:     "123",
				Query:  url.Values{"key": []string{"value"}},
			},
		},
		{
			name:     "with everything",
			expected: "did:example:123/foo?key=value#fragment",
			did: DID{
				Method:   "example",
				ID:       "123",
				Path:     "foo",
				Fragment: "fragment",
				Query:    url.Values{"key": []string{"value"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.did.String())
		})
	}
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
