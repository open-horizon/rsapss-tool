package main

import (
	"fmt"
	"github.com/open-horizon/rsapss-tool/generatekeys"
	"github.com/open-horizon/rsapss-tool/listkeys"
	"github.com/open-horizon/rsapss-tool/sign"
	"github.com/open-horizon/rsapss-tool/verify"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"
)

const (
	version                = "0.3.0"
	outputInfoPrefix       = "[INFO]"
	outputDebugPrefix      = "[DEBUG]"
	outputErrorPrefix      = "[ERROR]"
	signatureOkOutput      = "SIGOK"
	signatureInvalidOutput = "SIGINVALID"

	nokeysOutput = "NOKEYS"

	// 10 years, 2 leap days and 1 day for padding
	maxSelfSignedCertExpirationDays = 3653

	// default subdir path (of $HOME) for this tool's state
	rsapssHomeDirSuffix = ".rsapsstool"

	rsapssUserKeysDirName = "keypairs"

	// default directory for installing pubkeys locally
	horizonDefaultUserKeysDir = "/var/horizon/userkeys"
)

var rsapssHomeDefault string
var rsapssUserKeysDirValuePlaceholder string

func init() {
	currUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Unable to determine current user.\n", outputErrorPrefix)
		os.Exit(2)
	}

	rsapssHomeDefault = path.Join(currUser.HomeDir, rsapssHomeDirSuffix)
	rsapssUserKeysDirValuePlaceholder = fmt.Sprintf("<rsapsshome>/%s", rsapssUserKeysDirName)
}

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

func listKeysAction(ctx *cli.Context) error {
	keysDir := ctx.String("keypairsdir")
	if keysDir == "" {
		return cli.NewExitError("Required option 'keypairsdir' not provided. Use the '--help' option for more information.", 2)
	} else if keysDir == rsapssUserKeysDirValuePlaceholder {
		// N.B. special case: use the global option rsapsshome as prefix in path
		keysDir = fmt.Sprintf("%v/%v", ctx.GlobalString("rsapsshome"), rsapssUserKeysDirName)
	}

	if ctx.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "%s Visiting key storage dir %s\n", outputInfoPrefix, keysDir)
	}

	list, err := listkeys.ListPairs(keysDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Unable to read keys in given directory, %v. Error: %v\n", outputErrorPrefix, keysDir, err)
		return cli.NewExitError(fmt.Sprintf("Key listing error %v", keysDir), 3)
	}

	if ctx.GlobalBool("debug") {
		fmt.Fprintf(os.Stderr, "%s Raw Key list: %v\n", outputInfoPrefix, list)
	}

	if len(list) == 0 {
		fmt.Printf("%v\n", nokeysOutput)
	} else {
		fmt.Fprintf(os.Stderr, "%s Summarizing x509 Certificates found in directory %s. For more detail, execute `openssl x509 -noout -text -in <cert_filepath> -inform DER`\n", outputInfoPrefix, keysDir)

		// use template to do pretty-printed output
		t := template.Must(template.New("keylist.tmpl").Funcs(map[string]interface{}{"separator": func(s string) string {
			return strings.Repeat("-", utf8.RuneCountInString(s))
		}}).ParseFiles("keylist.tmpl"))
		if err := t.Execute(os.Stdout, list); err != nil {
			fmt.Fprintf(os.Stderr, "%s Unable to format key list output: %v\n", outputErrorPrefix, err)
		}
	}

	return nil
}

func generateNewKeysAction(ctx *cli.Context) error {
	outputDir := ctx.String("outputdir")
	if outputDir == "" {
		return cli.NewExitError("Required option 'outputdir' not provided. Use the '--help' option for more information.", 2)
	} else if outputDir == rsapssUserKeysDirValuePlaceholder {
		// N.B. special case: use the global option rsapsshome as prefix in path
		outputDir = fmt.Sprintf("%v/%v", ctx.GlobalString("rsapsshome"), rsapssUserKeysDirName)

		err := os.MkdirAll(outputDir, 0700)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to create userkeysdir in rsapsshome %v\n", outputErrorPrefix, err)
			return cli.NewExitError(fmt.Sprintf("Unable to use output directory '%v'", outputDir), 2)
		}
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

	// TODO: validate org and cn?
	orgI := ctx.String("x509org")
	if orgI == "" {
		return cli.NewExitError("Required option 'x509org' not provided. Use the '--help' option for more information.", 2)
	}

	cnI := ctx.String("x509cn")
	if orgI == "" {
		return cli.NewExitError("Required option 'x509cn' not provided. Use the '--help' option for more information.", 2)
	}

	daysValidI := ctx.Int("x509daysvalid")
	if daysValidI < 1 || daysValidI > maxSelfSignedCertExpirationDays {
		return cli.NewExitError(fmt.Sprintf("x509 certificate validity date argument invalid. Please specify a number of days greater than 1 and less than %d", maxSelfSignedCertExpirationDays), 2)
	}

	newKeys, err := generatekeys.Write(outputDir, ctx.Int("keylength"), cnI, orgI, time.Now().AddDate(0, 0, daysValidI))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error generating new keys: %v\n", outputErrorPrefix, err)
		return cli.NewExitError("Failed to generate new keys", 3)
	}
	fmt.Fprintf(os.Stderr, "%s Sucessfully generated new keys for common name '%s' in organization '%s': %v\n", outputInfoPrefix, cnI, orgI, newKeys)
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
		cli.StringFlag{
			Name:   "rsapsshome",
			Value:  rsapssHomeDefault,
			Usage:  "Home directory for state managed by this tool",
			EnvVar: "RSAPSSTOOL_HOME",
		},
		cli.BoolFlag{
			Name:   "debug",
			EnvVar: "RSAPSSTOOL_DEBUG",
		},
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
					Name: "outputdir, d",
					// TODO: figure out if there's a way to set the value of this using the home dir set by global option
					Value:  rsapssUserKeysDirValuePlaceholder,
					Usage:  "Path to which private/public keypair will be written",
					EnvVar: "RSAPSSTOOL_GENOUTPUTDIR",
				},
				cli.IntFlag{
					Name:   "keylength, l",
					Value:  4096,
					Usage:  "Length of the generated keys",
					EnvVar: "RSAPSSTOOL_GENKEYLEN",
				},
				cli.StringFlag{
					Name:   "x509org, xo",
					Usage:  "x509 certificate Organization (O) field",
					EnvVar: "RSAPSSTOOL_X509ORG",
				},
				cli.StringFlag{
					Name:   "x509cn, xcn",
					Usage:  "x509 certificate Common Name (CN) field",
					EnvVar: "RSAPSSTOOL_X509CN",
				},
				cli.IntFlag{
					Name:   "x509daysvalid, xdv",
					Value:  1461,
					Usage:  "x509 certificate validity (Validity > Not After) expressed in days from the day of generation",
					EnvVar: "RSAPSSTOOL_X509DAYSVALID",
				},
			},
			Action: generateNewKeysAction,
		},

		cli.Command{
			Name:    "listkeypairs",
			Aliases: []string{"lk"},
			Usage:   fmt.Sprintf("List certificate and private key pairs in %v", rsapssUserKeysDirValuePlaceholder),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "keypairsdir, d",
					Value:  rsapssUserKeysDirValuePlaceholder,
					Usage:  "Path to read keypairs from",
					EnvVar: "RSAPSSTOOL_KEYPAIRSDIR",
				},
			},
			Action: listKeysAction,
		},
	}

	app.Before = func(ctx *cli.Context) error {
		if ctx.Bool("debug") {
			fmt.Fprintf(os.Stderr, "%s Debug output enabled\n", outputInfoPrefix)
		}

		rsapssHome, err := filepath.Abs(ctx.String("rsapssHome"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Configuration error: %v\n", outputErrorPrefix, err)
			return cli.NewExitError("rsapss-tool home directory (argument rsapsstoolhome) is not resolvable", 2)
		}

		err = os.MkdirAll(rsapssHome, 0700)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Configuration error: %v\n", outputErrorPrefix, err)
			return cli.NewExitError("rsapss-tool home directory (argument rsapsstoolhome) is not usable", 2)
		}

		fmt.Fprintf(os.Stderr, "%s Using rsapss-tool home directory %v\n", outputInfoPrefix, rsapssHome)
		return nil
	}

	app.Run(os.Args)

	fmt.Fprintf(os.Stderr, "%s Exiting\n", outputInfoPrefix)
	os.Exit(0)
}
