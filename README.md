# rsapss-tool

A Standalone CLI tool and library for working with RSA PSS keys and using them.

## Use

### CLI Tool

The default `make` target for this project produces the binary `rsapss-tool`. The tool includes argument and mode help:

    rsapss-tool --help

    NAME:
       rsapsstool - Sign, verify payloads using RSA PSS keys, or generate new keys

    USAGE:
       rsapss-tool [global options] command [command options] [arguments...]

    VERSION:
       0.1.0

    COMMANDS:
         sign, s              Sign a payload with provided RSA PSS private key
         verify, v            Verify the signature of a payload with provided RSA PSS public key
         generatenewkeys, gk  Generate a new private/public keypair
         help, h              Shows a list of commands or help for one command

    GLOBAL OPTIONS:
       --debug         [$RSAPSSTOOL_DEBUG]
       --help, -h     show help
       --version, -v  print the version
    [INFO] Exiting.

#### Sample use:

    rsapss-tool gk --keylength 1024 --outputdir /tmp
    printf "somecontent" | rsapss-tool sign --privatekey /tmp/private.key > /tmp/somecontent.signature
    printf "somecontent" | rsapss-tool verify --publickey /tmp/public.key -x /tmp/somecontent.signature 2>/dev/null | grep SIG
    printf "some OTHER content" | rsapss-tool verify --publickey /tmp/public.key -x /tmp/somecontent.signature
    echo $?

It's possible to specify command options with envvars, for instance `--debug` can be enabled like this:

    printf "some OTHER content" | RSAPSSTOOL_DEBUG=true rsapss-tool verify --publickey /tmp/public.key -x /tmp/somecontent.signature

See the tool's help output for the names of envvars that corresond to command options.

### Library

## Development

### Make information

The `Makefile` in this project fiddles with the `$GOPATH` and fetches dependencies so that `make` targets can be executed outside of the `$GOPATH`. Some of this tomfoolery is hidden in normal build output. To see `make`'s progress, execute `make` with the argument `VERBOSE=y`.

Notable `make` targets include:

 * `all` - Compile source and produce `rsapss-tool` binary
 * `clean` - Clean build artifacts
 * `lint` - Execute Golang code analysis tools to report ill code style
 * `check` - Execute both unit and integration tests
