package main

import (
	"fmt"
	"github.com/open-horizon/rsapss-tool/generatekeys"
	"github.com/open-horizon/rsapss-tool/sign"
	"github.com/open-horizon/rsapss-tool/verify"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

const (
	version                = "0.1.0"
	outputInfoPrefix       = "[INFO]"
	outputDebugPrefix      = "[DEBUG]"
	outputErrorPrefix      = "[ERROR]"
	signatureOkOutput      = "SIGOK"
	signatureInvalidOutput = "SIGINVALID"
)

func readInput(input *os.File, debug bool) ([]byte, error) {
	bytes, err := ioutil.ReadAll(input)
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "%s could not read input: %v\n", outputErrorPrefix, err)
		return nil, cli.NewExitError("Failed to read input", 3)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "%s read input: %v\n", outputDebugPrefix, strings.TrimSuffix(string(bytes), "\n"))
	}
	return bytes, nil
}

func generateNewKeysAction(ctx *cli.Context) error {
	outputDir := ctx.String("outputdir")
	if outputDir == "" {
		return cli.NewExitError("Required option 'outputDir' not provided. Use the '--help' option for more information.", 2)
	}

	outputCheck, err := os.Stat(outputDir)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to stat given directory %v", outputDir), 2)
	}

	switch mode := outputCheck.Mode(); {
	case mode.IsDir():
		fmt.Fprintf(os.Stderr, "%s Writing new keys to outputdir: %v\n", outputInfoPrefix, outputDir)
	default:
		return cli.NewExitError(fmt.Sprintf("Given directory path (%v) unusable", outputDir), 2)
	}

	newKeys, err := generatekeys.Write(outputDir, ctx.Int("keylength"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error generating new keys: %v\n", outputErrorPrefix, err)
		return cli.NewExitError("Failed to generate new keys", 3)
	}
	fmt.Fprintf(os.Stderr, "%s Sucessfully generated new keys %v\n", outputInfoPrefix, newKeys)
	fmt.Println("Wrote keys:")
	for _, key := range newKeys {
		fmt.Printf("\t%v\n", key)
	}

	return nil
}

func signAction(ctx *cli.Context) error {
	key := ctx.String("privatekey")
	if key == "" {
		return cli.NewExitError("Required option 'privatekey' not provided. Use the '--help' option for more information.", 2)
	}

	fmt.Fprintf(os.Stderr, "%s Using privatekey: %v\n", outputInfoPrefix, key)

	bytes, err := readInput(os.Stdin, ctx.GlobalBool("debug"))
	if err != nil {
		return err
	}

	signature, err := sign.Input(key, bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Signing error: %v\n", outputErrorPrefix, err)
		return cli.NewExitError("Failed to sign input", 3)
	}

	fmt.Printf("%s\n", string(signature))
	return nil
}

func verifyAction(ctx *cli.Context) error {
	keyPath := ctx.String("publickey")
	if keyPath == "" {
		return cli.NewExitError("Required option 'publickey' not provided. Use the '--help' option for more information.", 2)
	}

	fmt.Fprintf(os.Stderr, "%s Using publickey: %v\n", outputInfoPrefix, keyPath)

	inputBytes, err := readInput(os.Stdin, ctx.GlobalBool("debug"))
	if err != nil {
		return err
	}

	signaturePath := ctx.String("signature")
	if signaturePath == "" {
		return cli.NewExitError("Required option 'signature' not provided. Use the '--help' option for more information.", 2)
	}

	file, err := os.Open(signaturePath)
	if err != nil {
		return cli.NewExitError("Unable to open file at given signature file path.", 2)
	}
	defer file.Close()

	signatureBytes, err := readInput(file, ctx.GlobalBool("debug"))
	if err != nil {
		return err
	}

	verified, err := verify.Input(keyPath, string(signatureBytes), inputBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", outputInfoPrefix, err)
		return cli.NewExitError("Unable to verify signature", 2)
	} else if !verified {
		fmt.Println(signatureInvalidOutput) // stable, parseable token expected to be on its own line
		return cli.NewExitError("Signature invalid", 5)
	} else {
		fmt.Println(signatureOkOutput) // stable, parseable token expected to be on its own line
		fmt.Println("Signature valid") // informational
		return nil
	}
}

func main() {
	app := cli.NewApp()
	app.EnableBashCompletion = true

	app.Name = "rsapsstool"
	app.Version = version
	app.Usage = "Sign, verify payloads using RSA PSS keys, or generate new keys"

	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: "debug", EnvVar: "RSAPSSTOOL_DEBUG"},
	}

	app.Action = func(ctx *cli.Context) error {
		if ctx.Bool("debug") {
			fmt.Fprintf(os.Stderr, "%s debug output enabled.\n", outputInfoPrefix)
		}
		return nil
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:    "sign",
			Aliases: []string{"s"},
			Usage:   "Sign a payload with provided RSA PSS private key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "privatekey, k",
					Value:  "",
					Usage:  "PEM-encoded private key to sign the payload",
					EnvVar: "RSAPSSTOOL_PRIVATEKEY",
				},
			},
			Action: signAction,
		},
		cli.Command{
			Name:    "verify",
			Aliases: []string{"v"},
			Usage:   "Verify the signature of a payload with provided RSA PSS public key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "publickey, k",
					Value:  "",
					Usage:  "PEM-encoded public key to sign the payload",
					EnvVar: "RSAPSSTOOL_PUBLICKEY",
				},
				cli.StringFlag{
					Name:   "signature, x",
					Value:  "",
					Usage:  "Path to signature file",
					EnvVar: "RSAPSSTOOL_SIGNATURE_FILE",
				},
			},
			Action: verifyAction,
		},
		cli.Command{
			Name:    "generatenewkeys",
			Aliases: []string{"gk"},
			Usage:   "Generate a new private/public keypair",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "outputdir, d",
					Value:  ".",
					Usage:  "Path to which private/public keypair will be written",
					EnvVar: "RSAPSSTOOL_GENOUTPUTDIR",
				},
				cli.IntFlag{
					Name:   "keylength, l",
					Value:  4096,
					Usage:  "Length of the generated keys",
					EnvVar: "RSAPSSTOOL_GENKEYLEN",
				},
			},
			Action: generateNewKeysAction,
		},
	}

	app.Run(os.Args)

	fmt.Fprintf(os.Stderr, "%s Exiting.\n", outputInfoPrefix)
	os.Exit(0)
}
