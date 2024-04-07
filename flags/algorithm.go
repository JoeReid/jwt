package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

type Algorithm string

const (
	AlgorithmHS256 Algorithm = "HS256"
	AlgorithmHS384 Algorithm = "HS384"
	AlgorithmHS512 Algorithm = "HS512"

	AlgorithmRS256 Algorithm = "RS256"
	AlgorithmRS384 Algorithm = "RS384"
	AlgorithmRS512 Algorithm = "RS512"

	AlgorithmES256 Algorithm = "ES256"
	AlgorithmES384 Algorithm = "ES384"
	AlgorithmES512 Algorithm = "ES512"

	AlgorithmPS256 Algorithm = "PS256"
	AlgorithmPS384 Algorithm = "PS384"
	AlgorithmPS512 Algorithm = "PS512"

	AlgorithmNONE Algorithm = "none"
)

func (a *Algorithm) String() string {
	return string(*a)
}

func (a *Algorithm) Set(v string) error {
	switch v {
	case string(AlgorithmHS256):
		*a = AlgorithmHS256
		return nil

	case string(AlgorithmHS384):
		*a = AlgorithmHS384
		return nil

	case string(AlgorithmHS512):
		*a = AlgorithmHS512
		return nil

	case string(AlgorithmRS256):
		*a = AlgorithmRS256
		return nil

	case string(AlgorithmRS384):
		*a = AlgorithmRS384
		return nil

	case string(AlgorithmRS512):
		*a = AlgorithmRS512
		return nil

	case string(AlgorithmES256):
		*a = AlgorithmES256
		return nil

	case string(AlgorithmES384):
		*a = AlgorithmES384
		return nil

	case string(AlgorithmES512):
		*a = AlgorithmES512
		return nil

	case string(AlgorithmPS256):
		*a = AlgorithmPS256
		return nil

	case string(AlgorithmPS384):
		*a = AlgorithmPS384
		return nil

	case string(AlgorithmPS512):
		*a = AlgorithmPS512
		return nil

	case string(AlgorithmNONE):
		*a = AlgorithmNONE
		return nil

	default:
		return fmt.Errorf("invalid algorithm: %s", v)
	}
}

func (a *Algorithm) Type() string {
	return "algorithm"
}

func AlgorithmCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{
		string(AlgorithmHS256) + "\tHMAC using SHA-256",
		string(AlgorithmHS384) + "\tHMAC using SHA-384",
		string(AlgorithmHS512) + "\tHMAC using SHA-512",

		string(AlgorithmRS256) + "\tRSASSA-PKCS1-v1_5 using SHA-256",
		string(AlgorithmRS384) + "\tRSASSA-PKCS1-v1_5 using SHA-384",
		string(AlgorithmRS512) + "\tRSASSA-PKCS1-v1_5 using SHA-512",

		string(AlgorithmES256) + "\tECDSA using P-256 and SHA-256",
		string(AlgorithmES384) + "\tECDSA using P-384 and SHA-384",
		string(AlgorithmES512) + "\tECDSA using P-521 and SHA-512",

		string(AlgorithmPS256) + "\tRSASSA-PSS using SHA-256 and MGF1 with SHA-256",
		string(AlgorithmPS512) + "\tRSASSA-PSS using SHA-384 and MGF1 with SHA-384",
		string(AlgorithmPS384) + "\tRSASSA-PSS using SHA-512 and MGF1 with SHA-512",
		string(AlgorithmNONE),
	}, cobra.ShellCompDirectiveDefault
}
