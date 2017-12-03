# rsapss-tool

A Standalone CLI tool and library for working with RSA PSS keys and using them.

## Use

### Building and installing

The default `make` target for this project produces the binary `rsapss-tool`.

The `go install` tool can be used to install the binary in `$GOPATH/bin` _**if**_ you have this project directory in your `$GOPATH`.

### CLI Tool

#### Inline help

The CLI binary includes help:

    NAME:
       rsapsstool - Sign, verify payloads using RSA PSS keys, or generate new keys

    USAGE:
       rsapss-tool [global options] command [command options] [arguments...]

    VERSION:
       0.3.0

    COMMANDS:
         sign, s              Sign a payload with provided RSA PSS private key
         verify, v            Verify the signature of a payload with provided RSA PSS public key
         generatenewkeys, gk  Generate a new private/public keypair; output both with public key wrapped in x509 certificate
         listkeypairs, lk     List certificate and private key pairs in <rsapsshome>/keypairs
         help, h              Shows a list of commands or help for one command

    GLOBAL OPTIONS:
       --rsapsshome value  Home directory for state managed by this tool (default: "/home/mdye/.rsapsstool") [$RSAPSSTOOL_HOME]
       --debug              [$RSAPSSTOOL_DEBUG]
       --help, -h          show help
       --version, -v       print the version
    [INFO] Exiting

#### Sample invocations

 Below is a sequence of commands showing generation of new RSA PSS keys and use of them. Different forms of configuration options are used to show variety of supported invocations.

    rsapss-tool gk --keylength 8192 --x509org "Horizon" --x509cn "development@bluehorizon.network" --x509daysvalid 365
    rsapss-tool listkeypairs

    [INFO] Summarizing x509 Certificates found in directory /home/mdye/.rsapsstool/keypairs. For more detail, execute `openssl x509 -noout -text -in <cert_filepath> -inform PEM`

    Certificate (Horizon-6458f6e1efcbe13d5c567bd7c815ecfd0ea5459f-public.pem)
    -------------------------------------------------------------------------
      Serial Number: 64:58:f6:e1:ef:cb:e1:3d:5c:56:7b:d7:c8:15:ec:fd:0e:a5:45:9f
      Have Corresponding Private Key: true
      Issuer: <self>
      Validity:
        Not Before: 2017-12-03 10:09:00 +0000 UTC
        Not After: 2018-12-03 22:08:05 +0000 UTC
      Subject Names:
        commonName (CN): development@bluehorizon.network
        organizationName (O): Horizon


    [INFO] Exiting

    printf "somecontent" | rsapss-tool sign --privatekey $(ls ~/.rsapsstool/keypairs/*.key) > /tmp/somecontent.signature
    printf "somecontent" | rsapss-tool verify --publickey $(ls ~/.rsapsstool/keypairs/*.pem) -x /tmp/somecontent.signature 2>/dev/null | grep SIG
    printf "some OTHER content" | rsapss-tool verify --publickey $(ls ~/.rsapsstool/keypairs/*.pem) -x /tmp/somecontent.signature
    echo $?

It's possible to specify command options with envvars, for instance `--debug` can be enabled like this:

    printf "some OTHER content" | RSAPSSTOOL_DEBUG=true rsapss-tool verify --publickey $(ls ~/.rsapsstool/keypairs/*.pem) -x /tmp/somecontent.signature

See the tool's help output for the names of envvars that corresond to command options.

#### Program output

Output from the tool to `stdout` is intended for programmatic use — this is useful when authoring a script to sign content and capture only a generated signature, for instance. As a consequence, `stderr` is used to report both informational and error messages. Use the familiar Bash output handling mechanisms (`2>`, `1>`) to isolate `stdout` output.

Verification output to stdout is guaranteed to be stable. The text `SIGOK` will be printed to stdout iff a signature is verified. `SIGINVALID` indicates verification failure with key material, signature and input data that passed format and content checks.

#### Exit status codes

The following error codes are produced by the CLI tool under described conditions:

 * **2**: Tool error (an error not believed to have been caused by user)
 * **3**: CLI invocation error or user input error (for instance, a specified public key file could not be read or was ill-formatted)
 * **5**: Provided PSS signature is **not valid** for the given input and public key

### Library

See integration tests like [sign_int_test.go](sign/sign_int_test.go) for example usage.

## Development

### Make information

The `Makefile` in this project fiddles with the `$GOPATH` and fetches dependencies so that `make` targets can be executed outside of the `$GOPATH`. Some of this tomfoolery is hidden in normal build output. To see `make`'s progress, execute `make` with the argument `verbose=y`.

Notable `make` targets include:

 * `all` (default) - Compile source and produce `rsapss-tool` binary
 * `clean` - Clean build artifacts
 * `lint` - Execute Golang code analysis tools to report ill code style
 * `check` - Execute both unit and integration tests
