package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// TEMP: replaced in Task 2 with cobra root.
	fmt.Println("sophosfw", version)
	return nil
}
