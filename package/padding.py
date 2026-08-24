"""
package/padding.py

This file contains the padding function, which is called when the padding command is used.
"""

import getpass
import timeit
import base64

import pyperclip
from cryptography.hazmat.primitives import padding

from package import utils
from package.data import *


def padd(args):
    """ Functions for the padding command. """

    if args.getpass:
        function_input = getpass.getpass
    else:
        function_input = input

    args.algo = args.algo.upper()
    output_sup = []
    if args.time:
        timer = timeit.default_timer()

    if args.algo == "PKCS7":
        algo = padding.PKCS7
    elif args.algo == "ANSIX923":
        algo = padding.ANSIX923
    else:
        raise SystemExit(f"Error: Invalid algorithm: '{args.algo}'\n"
                         "Use the --list option to get the available algorithms.")

    if args.data:
        data_input = utils.input_load_bytes(args.data, "binary input data")
    else:
        if args.unpad:
            raise SystemExit(f"Error: The --text argument cannot be used with --unpad. Use --data to enter binary.")
        data_input = args.text.encode()
    if not args.block_size:
        if args.default:
            args.block_size = 128
        else:
            args.block_size = function_input(f"Block size (0/../[128]/../2040) : ")
        if args.block_size == "":
            args.block_size = 128
    try:
        args.block_size = int(args.block_size)
        if not args.block_size % 8 == 0 or not args.block_size <= 2040:
            raise ValueError
    except ValueError:
        raise SystemExit(f"Error: Invalid padding size: '{args.block_size}'\n")

    if not args.unpad:
        padder = algo(args.block_size).padder()
        padded_data = padder.update(data_input)
        padded_data += padder.finalize()
        if args.out_base64:
            output = base64.b64encode(padded_data).decode()
        else:
            output = base64.b16encode(padded_data).decode()
    else:
        unpadder = algo(args.block_size).unpadder()
        data = unpadder.update(data_input)
        data += unpadder.finalize()
        if args.out_base64:
            output = base64.b64encode(data).decode()
        else:
            try:
                output = data.decode()
            except UnicodeDecodeError:
                output = base64.b16encode(data).decode()

    if args.time:
        timer = timeit.default_timer() - timer
        output_sup.append(f"Generation time: {round(timer, 6)} s")

    # Output/results handling.
    total_output = f"{'\n'.join(output_sup)}\nResult: {output}"
    if not args.hide:
        print(total_output)
    if args.copy:
        pyperclip.copy(output)
    if args.output is not False:
        if args.output is None:
            utils.export_file("padding_result.txt", output.encode())
        else:
            utils.export_file(args.output, output.encode())
    if hasattr(args, 'output_all') and args.output_all is not False:
        if args.output_all is None:
            utils.export_file("padding_all_results.txt", total_output.encode())
        else:
            utils.export_file(args.output_all, total_output.encode())