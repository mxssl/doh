package main

import "github.com/mxssl/doh/cmd"

var (
	version = "dev"
	commit  = "none"
)

func main() {
	cmd.Execute(version, commit)
}
