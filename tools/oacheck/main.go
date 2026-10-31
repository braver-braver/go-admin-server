// oacheck loads and validates an OpenAPI document (default api/openapi.yaml).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/getkin/kin-openapi/openapi3"
)

func main() {
	path := "api/openapi.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	doc, err := openapi3.NewLoader().LoadFromFile(path)
	if err == nil {
		err = doc.Validate(context.Background())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, path+":", err)
		os.Exit(1)
	}
	fmt.Printf("%s: %d paths, valid\n", path, len(doc.Paths.Map()))
}
