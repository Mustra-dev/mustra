// sensor-builder is invoked only in the resource-limited, network-isolated tools service.
package main

import (
	"context"
	"encoding/json"
	"github.com/mustra-dev/mustra/internal/sensorbuild"
	"io"
	"os"
)

func main() {
	var r sensorbuild.Request
	if json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&r) != nil {
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(sensorbuild.Build(context.Background(), r))
}
