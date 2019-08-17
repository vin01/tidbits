#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
from os.path import expanduser
from os import getcwd
import yaml
import gnupg

HOME = expanduser("~")
PWD = getcwd()

PARSER = argparse.ArgumentParser(description="""
                   Encrypt provided yaml keys with gpg to craft valid
                   yaml output. Prompt for values if: keys have no value
                   """)

PARSER.add_argument("infile", type=str, nargs=1,
                    help="Ansolute or relative path to the source yaml file")

PARSER.add_argument("keys", nargs="*",
                    help="Keys to be encrypted")

PARSER.add_argument("--outext", type=str, nargs="?", default=".asc",
                    help='Extension for output file with encrypted yaml values')

PARSER.add_argument("--gnupghome", type=str, nargs="?", default=".gnupg",
                    help="""Absolute or relative path to GnuPG home directory.
                          Defaults to .gnupg in home directory for user executing the command""")

PARSER.add_argument("--recipients", nargs="*", default=["salt-test"],
                    help="""ecipients whose public keys shall be used for encryption.
                          Defaults to ["salt-test"]""")

PARSER.add_argument("--shebang", type=str, nargs="?", default="yaml|gpg",
                    help="Shebang header for output file with encrypted yaml values")

PARSER.add_argument("--noenc-empty", type=bool, nargs="?", default=False,
                    help="Encrypt all keys which have empty values")

PARSER.add_argument("--enc-all", type=bool, nargs="?", default=False,
                    help="Encrypt all keys")

args = PARSER.parse_args()

ENC_ALL = args.enc_all
NOENC_EMPTY = args.noenc_empty
RECIPIENTS = args.recipients
SHEBANG = args.shebang
KEYS_TO_ENCRYPT = args.keys

if args.enc_all is None:
    ENC_ALL = True
if args.noenc_empty is None:
    NOENC_EMPTY = True

if not args.gnupghome.startswith("/"):
    GNUPGHOME = "{0}/{1}".format(HOME, args.gnupghome)
else:
    GNUPGHOME = args.gnupghome

if not args.infile[0].startswith("/"):
    INFILE = "{0}/{1}".format(PWD, args.infile[0])
else:
    INFILE = args.infile[0]

OUTFILE = "{0}{1}".format(INFILE, args.outext)

print("Using {0} as gnupg home".format(GNUPGHOME))
GPG = gnupg.GPG(gnupghome=GNUPGHOME)


yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str


def repr_str(dumper, data):
    """
    Handle newlines for GPG text to create valid yaml block
    """
    if "\n" in data:
        return dumper.represent_scalar(u"tag:yaml.org,2002:str", data, style="|")
    return dumper.org_represent_str(data)


yaml.add_representer(str, repr_str, Dumper=yaml.SafeDumper)


def gpg_encrypt(plaintext, recipients=RECIPIENTS):
    """
    GPG encrypt the plaintext
    """
    enc_data = GPG.encrypt(str(plaintext), recipients, always_trust=True)
    if not enc_data:
        print("Encryption failed. Need human support")
        sys.exit(1)
    return str(enc_data)


def yaml_encrypt(yaml_dict):
    """
    Recursively search for specified keys and gpg encrypt their values.
    """
    for key, val in yaml_dict.items():
        if isinstance(val, dict):
            if key in KEYS_TO_ENCRYPT:
                print("{0} is a dictionary, skipping encryption".format(key))
            yaml_dict[key] = yaml_encrypt(val)
        else:
            if key in KEYS_TO_ENCRYPT or (not val and not NOENC_EMPTY) or ENC_ALL:
                if isinstance(val, list):
                    # TODO: Support prompting for empty sequence values
                    enc_list = []
                    for elem in val:
                        print("Encrypting sequence {0}".format(key))
                        enc_list.append(gpg_encrypt(elem))
                    yaml_dict[key] = enc_list
                else:
                    print("Encrypting {0}".format(key))
                    if not val:
                        input_lines = []
                        print("Enter your content. Ctrl-D to save it.")
                        while True:
                            try:
                                line = input()
                            except EOFError:
                                break
                            input_lines.append(line)
                        val = '\n'.join(input_lines)
                    yaml_dict[key] = gpg_encrypt(val)
    return yaml_dict


print("Reading from {0}".format(INFILE))
with open(INFILE) as source:
    yaml_text = yaml.safe_load(source.read())
    encrypted_yaml = yaml_encrypt(yaml_text)

print("Writing encrypted yaml output to {0}".format(OUTFILE))
with open(OUTFILE, "w") as enc_file:
    enc_file.write("#!{0}\n\n".format(SHEBANG))
    yaml.safe_dump(encrypted_yaml, enc_file, default_flow_style=False)
