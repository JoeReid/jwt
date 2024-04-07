package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JoeReid/jwt/flags"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"
)

type DebugTokenCmd struct {
	alg     flags.Algorithm
	keyFile flags.KeyFile
}

func (d *DebugTokenCmd) CMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug a token",
		Long: `Debug a token.

This command will take a token and decode it, printing out the header and payload.
If the token is signed it will also verify the signature using the provided key.`,
		RunE: d.run,
	}

	cmd.Flags().Var(&d.alg, "alg", "The algorithm to generate the key for.")
	cmd.RegisterFlagCompletionFunc("alg", flags.AlgorithmCompletion)

	cmd.Flags().VarP(&d.keyFile, "key", "k", "A file containing the key to use for verifying the token.")

	return cmd
}

func (d *DebugTokenCmd) run(cmd *cobra.Command, args []string) error {
	var encoded string

	if len(args) > 0 {
		encoded = args[0]
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		encoded = string(data)
	}

	segments := strings.Split(encoded, ".")
	if len(segments) != 3 {
		return fmt.Errorf("token must have 3 segments, found %d", len(segments))
	}

	output := []string{"", "", "Signature: "}
	for i, segment := range segments {
		if i == 2 {
			output[2] += segment
			continue
		}

		rawJSON, err := jwt.DecodeSegment(segment)
		if err != nil {
			return fmt.Errorf("failed to decode segment %d: %w", i, err)
		}

		var out bytes.Buffer
		if err := json.Indent(&out, rawJSON, "", "  "); err != nil {
			return fmt.Errorf("failed to pretty print json: %w", err)
		}
		output[i] = out.String()
	}

	fmt.Println(strings.Join(output, "\n"))
	return nil
}
