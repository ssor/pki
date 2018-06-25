[![Build
Status](https://travis-ci.org/google/easypki.svg?branch=master)](https://travis-ci.org/google/easypki)
[![codecov](https://codecov.io/gh/google/easypki/branch/master/graph/badge.svg)](https://codecov.io/gh/google/easypki)

easypki
======

Easypki attempts to make managing a Certificate Authority very easy.
Serial, index, etc, are formatted in a way to be compatible with openssl,
so you can use openssl for commands not implemented by easypki.

# Usage

Easypki usage is straighforward:

1. Init the directory you will use
2. Create the CA
3. Create certificates

Create an env.sh that you can source later (or add to your .bashrc)

```
export PKI_ROOT=/tmp/pki
export PKI_ORGANIZATION="Umbrella Corp"
export PKI_ORGANIZATIONAL_UNIT=IT
export PKI_COUNTRY=US
export PKI_LOCALITY="Agloe"
export PKI_PROVINCE="New York"
```

Before being able to create you certificates, you need to `init` the root directory.
It creates files and directories required by easypki.

```
mkdir $PKI_ROOT
easypki init
```

Args passed to create make the Common Name, here: "Umbrella Corp Global Authority"

```
easypki create --ca Umbrella Corp Global Authority
```

Then you can choose between server and client certificate, by default server is implied, to generate a client certificate add `--client`

Generate a wildcard certificate for your web apps:

```
easypki create --dns "*.umbrella.com" *.umbrella.com
```

Another example, a certificate for wiki and www:

```
easypki create --dns "www.umbrella.com" --dns "wiki.umbrella.com"  www.umbrella.com
```

For more info about available flags, checkout out the help `-h`

You will find the generated cert in `issued` and private key in `private`

# API

For the latest API:

```
import "gopkg.in/google/easypki.v1"
```

## Legacy API

API below pkg/ has been rewritten to allow extensibility in terms of PKI
storage and better readability.

If you used the legacy API that was only writing files to disk, a tag has been
applied so you can still import it:

```
import "gopkg.in/google/easypki.v0"
```

# Disclaimer

This is not an official Google product
