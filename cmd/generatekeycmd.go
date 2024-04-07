package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/JoeReid/jwt/flags"
	"github.com/spf13/cobra"
)

type GenerateKeyCmd struct {
	alg        flags.Algorithm
	keyFile    string
	pubKeyFile string
}

func (g *GenerateKeyCmd) CMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-key",
		Short: "Generate a key",
		Long:  `Generate a key.`,
		RunE:  g.run,
	}

	cmd.Flags().Var(&g.alg, "alg", "The algorithm to generate the key for.")
	cmd.RegisterFlagCompletionFunc("alg", flags.AlgorithmCompletion)

	cmd.Flags().StringVarP(&g.keyFile, "key", "k", "key", "The file to write the key to."+
		" <key>.pub will also be written if using asymmetric keys and --public-key is not set.")

	cmd.Flags().StringVarP(&g.pubKeyFile, "public-key", "p", "key.pub", "The file to write the public key to when using asymmetric keys."+
		" If not set the public key is assumed to be <key>.pub")

	return cmd
}

func (g *GenerateKeyCmd) run(cmd *cobra.Command, args []string) error {
	switch g.alg {
	case flags.AlgorithmHS256, flags.AlgorithmHS384, flags.AlgorithmHS512:
		secret := make([]byte, 64)
		if _, err := rand.Read(secret); err != nil {
			return err
		}

		f, err := os.Create(g.keyFile)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.Write([]byte(base64.StdEncoding.EncodeToString(secret)))
		return err

	case flags.AlgorithmRS256, flags.AlgorithmRS384, flags.AlgorithmRS512:
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		pkf, err := os.Create(g.keyFile)
		if err != nil {
			return err
		}
		defer pkf.Close()

		if err := pem.Encode(pkf, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		}); err != nil {
			return err
		}

		pubkf, err := os.Create(g.pubKeyFile)
		if err != nil {
			return err
		}
		defer pubkf.Close()

		return pem.Encode(pubkf, &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&pk.PublicKey),
		})

	case flags.AlgorithmES256, flags.AlgorithmES384, flags.AlgorithmES512:
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		pkf, err := os.Create(g.keyFile)
		if err != nil {
			return err
		}
		defer pkf.Close()

		pkCert, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			return err
		}

		if err := pem.Encode(pkf, &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: pkCert,
		}); err != nil {
			return err
		}

		pubkf, err := os.Create(g.pubKeyFile)
		if err != nil {
			return err
		}
		defer pubkf.Close()

		pubCert, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
		if err != nil {
			return err
		}

		return pem.Encode(pubkf, &pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubCert,
		})

	default:
		return fmt.Errorf("Algorithm %s not yet implemented", g.alg)
	}
}
