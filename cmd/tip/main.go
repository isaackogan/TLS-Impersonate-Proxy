package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	path := flag.String("config", "tip.yaml", "configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "tip:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	return fmt.Errorf("not implemented (config %s, version %s)", path, version)
}
