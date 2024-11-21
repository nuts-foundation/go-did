package ld

import (
	"github.com/piprate/json-gold/ld"
	"net/http"
)

type DocumentLoader = ld.DocumentLoader

func Loader() ld.DocumentLoader {
	return ld.NewDefaultDocumentLoader(http.DefaultClient)
}
