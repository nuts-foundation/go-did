package did

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDIDURL_UnmarshalJSON(t *testing.T) {
	const input = `"did:example:123"`
	id := DIDURL{}
	err := json.Unmarshal([]byte(input), &id)
	require.NoError(t, err)
	assert.Equal(t, "did:example:123", id.String())
}

func TestDIDURL_MarshalJSON(t *testing.T) {
	actual, err := json.Marshal(MustParseDIDURL("did:example:123"))
	require.NoError(t, err)
	assert.Equal(t, `"did:example:123"`, string(actual))
}

func TestParseDIDURL(t *testing.T) {
	t.Run("parse a DID URL", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:123/path?query#fragment")
		assert.Equal(t, "did:example:123/path?query=#fragment", id.String())
		assert.NoError(t, err)
	})
	t.Run("with escaped ID", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:fizz%20buzz")
		require.NoError(t, err)
		assert.Equal(t, "did:example:fizz%20buzz", id.String())
		assert.Equal(t, "fizz%20buzz", id.ID)
		assert.Equal(t, "fizz buzz", id.DecodedID)
	})
	t.Run("with fragment", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:123#fragment")
		require.NoError(t, err)
		assert.Equal(t, "did:example:123#fragment", id.String())
		assert.Equal(t, "fragment", id.Fragment)
	})
	t.Run("with escaped fragment", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:123#frag%20ment")
		require.NoError(t, err)
		assert.Equal(t, "did:example:123#frag%20ment", id.String())
		assert.Equal(t, "frag%20ment", id.Fragment)
		assert.Equal(t, "frag ment", id.DecodedFragment)
	})
	t.Run("with path", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:123/subpath")
		require.NoError(t, err)
		assert.Equal(t, "123", id.ID)
		assert.Equal(t, "subpath", id.Path)
	})
	t.Run("escaped path", func(t *testing.T) {
		id, err := ParseDIDURL("did:example:123/sub%20path")
		require.NoError(t, err)
		assert.Equal(t, "123", id.ID)
		assert.Equal(t, "sub%20path", id.Path)
		assert.Equal(t, "sub path", id.DecodedPath)
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
			assert.Equal(t, "did:web:example.com%3A3000:user:alice/foo/bar?param=value#fragment", id.String())
			assert.Equal(t, "web", id.Method)
			assert.Equal(t, "example.com%3A3000:user:alice", id.ID)
			assert.Equal(t, "foo/bar", id.Path)
			assert.Len(t, id.Query, 1)
			assert.Equal(t, "value", id.Query.Get("param"))
			assert.Equal(t, "fragment", id.Fragment)
		})
	})

	t.Run("ok - parsed DID URL equals constructed one", func(t *testing.T) {
		parsed, err := ParseDIDURL("did:example:123/path?key=value#fragment")
		require.NoError(t, err)
		constructed := DIDURL{
			DID: DID{
				Method:    "example",
				ID:        "123",
				DecodedID: "123",
			},
			Path:        "path",
			DecodedPath: "path",
			Query: url.Values{
				"key": []string{"value"},
			},
			Fragment:        "fragment",
			DecodedFragment: "fragment",
		}
		assert.Equal(t, constructed, *parsed)
	})
	t.Run("ok - parsed DID URL equals constructed one (no query)", func(t *testing.T) {
		parsed, err := ParseDIDURL("did:example:123/path#fragment")
		require.NoError(t, err)
		constructed := DIDURL{
			DID: DID{
				Method:    "example",
				ID:        "123",
				DecodedID: "123",
			},
			Path:            "path",
			DecodedPath:     "path",
			Fragment:        "fragment",
			DecodedFragment: "fragment",
		}
		assert.Equal(t, constructed, *parsed)
	})

	t.Run("percent-encoded characters in ID are allowed", func(t *testing.T) {
		parsed, err := ParseDIDURL("did:example:123%f8")
		require.NoError(t, err)
		constructed := DIDURL{
			DID: DID{
				Method:    "example",
				ID:        "123%f8",
				DecodedID: "123\xf8",
			},
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
				{name: "only fragment", did: "#fragment"},
				{name: "only query", did: "?key=value"},
				{name: "only query and fragment", did: "?key=value#fragment"},
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

func TestDIDURL_MarshalText(t *testing.T) {
	const expected = "did:example:123"
	id := MustParseDIDURL(expected)
	actual, err := id.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestDIDURL_Equal(t *testing.T) {
	t.Run("equal", func(t *testing.T) {
		d1 := MustParseDIDURL("did:example:123/foo?key=value#fragment")
		d2 := MustParseDIDURL("did:example:123/foo?key=value#fragment")
		assert.True(t, d1.Equals(d2))
	})
	t.Run("method differs", func(t *testing.T) {
		assert.False(t, MustParseDIDURL("did:example1:123").Equals(MustParseDIDURL("did:example:123")))
	})
	t.Run("ID differs", func(t *testing.T) {
		assert.False(t, MustParseDIDURL("did:example:1234").Equals(MustParseDIDURL("did:example:123")))
	})
	t.Run("one DID is empty", func(t *testing.T) {
		assert.False(t, MustParseDIDURL("did:example:1234").Equals(DIDURL{}))
	})
	t.Run("both DIDs are empty", func(t *testing.T) {
		assert.True(t, DIDURL{}.Equals(DIDURL{}))
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
	t.Run("empty query (self)", func(t *testing.T) {
		d1 := MustParseDIDURL("did:example:123/foo")
		d2 := MustParseDIDURL("did:example:123/foo?")
		assert.True(t, d1.Equals(d2))
	})
	t.Run("empty query (self)", func(t *testing.T) {
		d1 := MustParseDIDURL("did:example:123/foo?")
		d2 := MustParseDIDURL("did:example:123/foo")
		assert.True(t, d1.Equals(d2))
	})
	t.Run("path differs", func(t *testing.T) {
		d1 := MustParseDIDURL("did:example:123/fuzz?key=value#fragment")
		d2 := MustParseDIDURL("did:example:123/fizz?key=value#fragment")
		assert.False(t, d1.Equals(d2))
	})
}

func TestDIDURL_String(t *testing.T) {
	type testCase struct {
		name     string
		expected string
		did      DIDURL
	}
	testCases := []testCase{
		{
			name:     "basic DID",
			expected: "did:example:123",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
			},
		},
		{
			name:     "empty DID",
			expected: "",
			did:      DIDURL{},
		},
		{
			name:     "with path",
			expected: "did:example:123/foo",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
				Path: "foo",
			},
		},
		{
			name:     "with escapable characters in path",
			expected: "did:example:123/fizz%20buzz",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
				Path: "fizz%20buzz",
			},
		},
		{
			name:     "with fragment",
			expected: "did:example:123#fragment",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
				Fragment: "fragment",
			},
		},
		{
			name:     "with escapable characters in fragment",
			expected: "did:example:123#fizz%20buzz",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
				Fragment: "fizz%20buzz",
			},
		},
		{
			name:     "with query",
			expected: "did:example:123?key=value",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
				Query: url.Values{"key": []string{"value"}},
			},
		},
		{
			name:     "with everything",
			expected: "did:example:123/foo?key=value#fragment",
			did: DIDURL{
				DID: DID{
					Method: "example",
					ID:     "123",
				},
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

func TestDIDURL_Empty(t *testing.T) {
	t.Run("DID", func(t *testing.T) {
		assert.False(t, MustParseDIDURL("did:example:123").Empty())
	})
	t.Run("DID URL", func(t *testing.T) {
		assert.False(t, MustParseDIDURL("#fragment").Empty())
	})
	t.Run("empty when just generated", func(t *testing.T) {
		id := DIDURL{}
		assert.True(t, id.Empty())
	})
}

func TestDIDURL_URI(t *testing.T) {
	type testCase struct {
		name     string
		expected string
	}
	testCases := []testCase{
		{
			name:     "just DID",
			expected: "did:example:123",
		},
		{
			name:     "with path",
			expected: "did:example:123/foo",
		},
		{
			name:     "with query",
			expected: "did:example:123?key=value",
		},
		{
			name:     "with fragment",
			expected: "did:example:123#fragment",
		},
		{
			name:     "with everything",
			expected: "did:example:123/foo?key=value#fragment",
		},
		{
			name:     "without DID",
			expected: "/foo?key=value#fragment",
		},
		{
			name:     "just fragment",
			expected: "#fragment",
		},
		{
			name:     "just query",
			expected: "?key=value",
		},
		{
			name:     "just path",
			expected: "/foo",
		},
		{
			name:     "with escaped path",
			expected: "/foo%20bar?key=value#fragment",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id := MustParseDIDURL(tc.expected)
			assert.Equal(t, tc.expected, id.URI().String())
		})
	}
}
