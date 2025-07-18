package main

import (
	"domain_watcher/cmd"
	"log"
	"os"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("domain_watcher: ")
	log.SetOutput(os.Stderr)
}

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
