package main

import (
	"os"

	"github.com/JoeReid/jwt/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
