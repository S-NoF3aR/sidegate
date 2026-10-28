// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/s-nof3ar/sidegate/terraform-provider-sidegate/internal/provider"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/s-nof3ar/sidegate",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
