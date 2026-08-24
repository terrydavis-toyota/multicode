"""
package/signature.py

This file contains the signature function, which is called when the signature command is used.
"""

import importlib
import timeit
import base64

import pyperclip

from package.data import *
from package import utils


def signature(args):
    """ Function for the signature command. """

    # Find the algorithm that the user has set as argument and import the corresponding module.
    if args.algo in SIGN_ALGO_MODULES:
        module_sign = importlib.import_module(SIGN_ALGO_MODULES[args.algo][0])
        module_key = importlib.import_module(f"Cryptodome.{SIGN_ALGO_MODULES[args.algo][1]}")
        module_hash = importlib.import_module(f"Cryptodome.Hash.SHA256")
    else:
        raise SystemExit(f"Error: Invalid algorithm: '{args.algo}'\n"
                         "Use the --list option to get the available algorithms.")

    # Handling arguments (default values, argument errors).
    try:
        if args.passphrase:
            key = module_key.import_key(utils.import_file(args.key), passphrase=args.passphrase)
        else:
            key = module_key.import_key(utils.import_file(args.key))
    except ValueError:
        raise SystemExit("Error: The key file is not in the right format or is encrypted."
                         "\nUse the --passphrase option to decrypt the key file.")
    if args.text:
        input_message = args.text.encode()
    elif args.file:
        input_message = utils.import_file(args.file)
    elif args.data:
        input_message = utils.input_load_bytes(args.data, "binary input data")
    else:
        input_message = input("Text signed or to be signed: ").encode()

    # Signature generation.
    output_sup = []
    if args.time:
        timer = timeit.default_timer()
    try:
        if args.algo == "eddsa":
            signature_object = module_sign.new(key, "rfc8032")
            message = input_message
        else:
            message = module_hash.new(input_message)
            if args.algo == "dss":
                signature_object = module_sign.new(key, 'fips-186-3')
            else:
                signature_object = module_sign.new(key)
        if args.sign:
            output = signature_object.sign(message)
            if args.out_base64:
                output = base64.b64encode(output).decode()
            else:
                output = base64.b16encode(output).decode()
        else:
            output = "The signature is authentic."
            try:
                try:
                    signature_object.verify(message, base64.b16decode(args.verify))
                except ValueError:
                    signature_object.verify(message, base64.b64decode(args.verify))
            except ValueError:
                output = "The signature is not authentic."
    except ValueError as e:
        raise SystemExit(f"Invalid value: {e}")
    if args.time:
        timer = timeit.default_timer() - timer
        output_sup.insert(0, f"Generation time: {round(timer, 6)} s")

    # Output/results handling.
    total_output = f"{'\n'.join(output_sup)}\n{output}"
    if not args.hide:
        print(total_output)
    if args.copy:
        pyperclip.copy(output)
    if args.output is not False:
        if args.output is None:
            utils.export_file("signature_output.txt", output)
        else:
            utils.export_file(args.output, output)
    if hasattr(args, 'output_all') and args.output_all is not False:
        if args.output_all is None:
            utils.export_file("signature_outputs.txt", total_output.encode())
        else:
            utils.export_file(args.output_all, total_output.encode())