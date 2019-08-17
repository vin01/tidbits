## What is it ?

A collection of code snippets and scripts to speed up daily terminal life.

## Brief descriptions

### dnsniff.py

Sniff DNS queries and responses on the host. Helpful for passive DNS monitoring, collection and incident response.

### obb_cli.py

Search Openbugbounty platform for specified domains.

```
NAME
    obb_cli.py search - Return the search results from OBB for specified domain(s).

SYNOPSIS
    obb_cli.py search DOMAINS <flags>

DESCRIPTION
    domains : tuple
        Domain(s) to search. Either python list, tuple format or just comma separated values.
    raw: bool
        Print output in raw format with all fields.
    payload: bool
       Print payload info as well from the vulnerability report page(s) for unpatched vulnerabilities.

POSITIONAL ARGUMENTS
    DOMAINS

FLAGS
    --raw=RAW
    --payload=PAYLOAD
```

### yaml_encrypt.py

GPG encrypts values of yaml keys (by a recursive search in the input file) based on following criteria:

- Empty yaml values
- Values of specified yaml keys (if any are specified)
- All values (if `--enc_all` is passed)

Helpful for encrypting sensitive data meant to be stored in yaml like [Saltstack Pillars](https://docs.saltstack.com/en/latest/ref/renderers/all/salt.renderers.gpg.html).

```
Encrypt provided yaml keys with gpg to craft valid yaml output. Prompt for
values if: keys have no value

positional arguments:
  infile                Ansolute or relative path to the source yaml file
  keys                  Keys to be encrypted

optional arguments:
  -h, --help            show this help message and exit
  --outext [OUTEXT]     Extension for output file with encrypted yaml values
  --gnupghome [GNUPGHOME]
                        Absolute or relative path to GnuPG home directory.
                        Defaults to .gnupg in home directory for user
                        executing the command
  --recipients [RECIPIENTS [RECIPIENTS ...]]
                        ecipients whose public keys shall be used for
                        encryption. Defaults to ["salt-test"]
  --shebang [SHEBANG]   Shebang header for output file with encrypted yaml
                        values
  --noenc-empty [NOENC_EMPTY]
                        Encrypt all keys which have empty values
  --enc-all [ENC_ALL]   Encrypt all keys
```
