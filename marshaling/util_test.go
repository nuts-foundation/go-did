package marshaling

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNormalizeDocument(t *testing.T) {
	t.Run("no keys", func(t *testing.T) {
		t.Run("single value, plural", func(t *testing.T) {
			actual, _ := NormalizeDocument([]byte(`{"message": "Hello, World"}`))
			assert.JSONEq(t, `{"message": "Hello, World"}`, string(actual))
		})
	})
	t.Run("string, plural", func(t *testing.T) {
		actual, _ := NormalizeDocument([]byte(`{"message": "Hello, World"}`), "message")
		assert.JSONEq(t, `{"message": ["Hello, World"]}`, string(actual))
	})
	t.Run("slice, plural", func(t *testing.T) {
		actual, _ := NormalizeDocument([]byte(`{"message": ["Hello, World"]}`), "message")
		assert.JSONEq(t, `{"message": ["Hello, World"]}`, string(actual))
	})
}
