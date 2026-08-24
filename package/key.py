"""
package/key.py

This file contains the key function, which is called when the key command is used.
"""

import importlib
import getpass
import timeit
import base64

import pyperclip

from package import utils
from package.data import *


def key(args):
    """ Functions for the key command. """

    # Handle the two optional positional arguments:
    # if the ALGORITHM argument is composed only of numbers and the NUMBITS argument is empty,
    # the two arguments are swapped.
    if args.algo and not args.bits:
        if args.algo.isdigit():
            args.bits = int(args.algo)
            args.algo = False

    # Find the algorithm that the user has set as argument and import the corresponding module.
    if not args.algo:
        module = importlib.import_module("Cryptodome.Random")
    else:
        module_algorithm = args.algo.upper()
        try:
            module = importlib.import_module(f"Cryptodome.PublicKey.{module_algorithm}")
        except ModuleNotFoundError:
            raise SystemExit(f"Error: Invalid algorithm: '{args.algo}'\n"
                             "Use the --list option to get the available algorithms.")

    # Handling arguments (default values, argument errors).
    if args.algo == "ecc":
        if args.bytes:
            raise SystemExit("multicode.py: error: argument --bytes/-b: not allowed with algorithm ecc")
        elif args.bits:
            raise SystemExit("multicode.py: error: argument NUMBITS: not allowed with algorithm ecc")
    elif args.curve:
        raise SystemExit("multicode.py: error: argument --curve is only allowed with the ecc algorithm.")
    if args.bytes and args.bits:
        raise SystemExit("multicode.py: error: argument --bytes/-b: not allowed with argument NUMBITS")
    elif args.bytes:
        args.bits = args.bytes*8
    if args.algo:
        if args.out_base64:
            raise SystemExit("multicode.py: error: argument --out-base64/-a: not allowed with argument ALGORITHM")
        if args.passphrase is None:
            if not args.default:
                args.passphrase = getpass.getpass("passphrase (empty: [no passphrase]): ")
        if not args.passphrase:
            args.passphrase = None
        if args.algo == "ecc" and args.curve is None:
            if not args.default:
                args.curve = input("Curve (../p256/../[ed25519]/..): ")
        if not args.curve:
            args.curve = "ed25519"
    else:
        for arg in ["passphrase", "openssh", "public"]:
            if getattr(args, arg):
                raise SystemExit(f"multicode.py: error: argument --{arg}: not allowed without argument ALGORITHM")
    if args.openssh:
        format_publickey = "OpenSSH"
    else:
        format_publickey = "PEM"

    # Key generation.
    output_total = []
    privatekey_output = ""
    publickey_output = ""
    if args.time:
        timer = timeit.default_timer()
    if not args.algo:
        if not args.bits:
            args.bits = 128
        elif int(args.bits % 8) != 0:
            raise SystemExit(f"Error: invalid bit value.\n"
                             "The bit value must be a multiple of 8, or use the --bytes BYTES option.")
        key_object = module.get_random_bytes(int(args.bits/8))
        if args.out_base64:
            privatekey_output = base64.b64encode(key_object).decode()
        else:
            privatekey_output = base64.b16encode(key_object).decode()
    elif args.algo in LIST_ALGO["key"]["public key algorithms"]:
        if args.public:
            try:
                key_object = module.import_key(utils.import_file(args.public), passphrase=args.passphrase)
                publickey_output = key_object.public_key().export_key(format=format_publickey).decode()
            except ValueError:
                raise SystemExit("Invalid private key: Incorrect format or encrypted key.")
        else:
            if args.algo == "ecc":
                key_object = module.generate(curve=args.curve)
                privatekey_output = key_object.export_key(format="PEM", passphrase=args.passphrase,
                                               protection="PBKDF2WithHMAC-SHA1AndAES128-CBC")
                publickey_output = key_object.public_key().export_key(format=format_publickey)
            else:
                if not args.bits:
                    args.bits = 2048
                try:
                    key_object = module.generate(args.bits)
                except ValueError:
                    raise SystemExit(f"Invalid bit value: {args.bits}. Cannot generate a key of this length.")
                privatekey_output = key_object.export_key(format="PEM", passphrase=args.passphrase).decode()
                publickey_output = key_object.public_key().export_key(format=format_publickey).decode()
    if args.time:
        timer = timeit.default_timer() - timer
        output_total.append(f"Generation time: {round(timer, 6)} s\n")

    # Output/results handling.
    output_total.append(f"\n{privatekey_output}")
    if publickey_output:
        output_total.append(f"\n{publickey_output}")
        if not privatekey_output:
            main_output = publickey_output
            name_fileout = "publickey.pem"
        else:
            main_output = privatekey_output
            name_fileout = "privatekey.pem"
    output_total = "".join(output_total)
    if not args.hide:
        print(output_total)
    if args.copy:
        pyperclip.copy(output_total)
    if args.output is not False:
        if args.output is None:
            utils.export_file(name_fileout, main_output)
        else:
            utils.export_file(args.output, main_output)
    if hasattr(args, 'output_all') and args.output_all is not False:
        if args.output_all is None:
            utils.export_file("allkeys.pem", output_total.encode())
        else:
            utils.export_file(args.output_all, output_total.encode())
    if args.output_public is not False:
        if args.output_public is None:
            utils.export_file("publickey.pem", publickey_output.encode())
        else:
            utils.export_file(args.output_public, publickey_output.encode())