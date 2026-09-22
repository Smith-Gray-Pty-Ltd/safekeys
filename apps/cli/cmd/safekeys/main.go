// Command safekeys is the operator and agent-facing CLI.
package main

import (
	"os"

	"github.com/Smith-Gray-Pty-Ltd/safekeys/apps/cli/internal/commands"
)

func main() {
	os.Exit(commands.Run(os.Args[1:]))
}
