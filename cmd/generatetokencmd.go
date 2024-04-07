package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/JoeReid/jwt/flags"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"
	"github.com/tidwall/sjson"
)

type GenerateTokenCmd struct {
	alg     flags.Algorithm
	keyFile flags.KeyFile

	expiresAfter time.Duration
	claims       []string
}

func (g *GenerateTokenCmd) CMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-token",
		Short: "Generate a token",
		Long:  `Generate a token.`,
		RunE:  g.run,
	}

	cmd.Flags().Var(&g.alg, "alg", "The algorithm to generate the key for.")
	cmd.RegisterFlagCompletionFunc("alg", flags.AlgorithmCompletion)

	cmd.Flags().VarP(&g.keyFile, "key", "k", "The key to use for signing the token.")

	cmd.Flags().DurationVarP(&g.expiresAfter, "expires-after", "e", time.Hour, "The time after which the token will expire. Default is 1 hour.")

	cmd.Flags().StringArrayVarP(&g.claims, "claim", "c", []string{}, "A claim to add to the token in the form of <key>=<value>."+
		" The key uses tidwall/sjson syntax to allow for nested keys. e.g. 'key.subkey=value'. "+
		" The flag can be used multiple times to add multiple claims.")

	return cmd
}

func (g *GenerateTokenCmd) run(cmd *cobra.Command, args []string) error {
	now := time.Now()

	jsonClaims, err := json.Marshal(&jwt.StandardClaims{
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(g.expiresAfter).Unix(),
	})
	if err != nil {
		return err
	}

	for _, claim := range g.claims {
		path, data, found := strings.Cut(claim, "=")
		if !found {
			return fmt.Errorf("Invalid claim format: %s", claim)
		}

		jsonClaims, err = sjson.SetRawBytes(jsonClaims, path, []byte(data))
		if err != nil {
			return err
		}
	}

	var claims jwt.MapClaims
	if err := json.Unmarshal(jsonClaims, &claims); err != nil {
		return err
	}

	if err := claims.Valid(); err != nil {
		return err
	}

	switch g.alg {
	case flags.AlgorithmHS256, flags.AlgorithmHS384, flags.AlgorithmHS512:
		key, err := g.keyFile.Secret()
		if err != nil {
			return err
		}

		tkn, err := jwt.NewWithClaims(jwt.GetSigningMethod(string(g.alg)), claims).SignedString(key)
		if err != nil {
			return err
		}

		fmt.Println(tkn)
		return nil

	case flags.AlgorithmRS256, flags.AlgorithmRS384, flags.AlgorithmRS512:
		key, err := g.keyFile.PrivateKey()
		if err != nil {
			return err
		}

		tkn, err := jwt.NewWithClaims(jwt.GetSigningMethod(string(g.alg)), claims).SignedString(key)
		if err != nil {
			return err
		}

		fmt.Println(tkn)
		return nil

	default:
		return fmt.Errorf("Algorithm %s not yet implemented", g.alg)
	}
}
