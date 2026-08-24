"""
package/otp.py

This file contains the otp function, which is called when the otp command is used.
"""

import importlib
import getpass
import timeit
import time
import os
import base64

import pyperclip
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from Cryptodome.Random import get_random_bytes

from package import utils
from package.data import *


def otp(args):
    """ Functions for the otp command. """

    if args.getpass:
        function_input = getpass.getpass
    else:
        function_input = input
    args.algo = args.algo.upper()
    args_dico = {}
    output_sup = []

    for arg in SPECS_OTPS[args.algo]["args"]:
        # For each parameter associated to the algorithm, check if it is in arguments or displays a prompt.
        if getattr(args, arg) is not False:
            args_dico[arg] = getattr(args, arg)
        elif args.default:
            args_dico[arg] = SPECS_OTPS[args.algo]["args"][arg]['default']
        else:
            args_dico[arg] = function_input(f"{arg[0].upper() + arg[1:].replace('_', ' ')}"
                                            f"{SPECS_OTPS[args.algo]["args"][arg]['prompt']}: ")
            if args_dico[arg] == "":
                args_dico[arg] = SPECS_OTPS[args.algo]["args"][arg]['default']


        if SPECS_OTPS[args.algo]["args"][arg]['type'] == bytes:
            # If the parameter is to be in binary,
            # generate or load the user input depending on whether he has entered a number or a string.
            if str(args_dico[arg]).isdigit():
                args_dico[arg] = get_random_bytes(int(int(args_dico[arg]) / 8))
                output_sup.append(f"{arg[0].upper() + arg[1:].replace('_', ' ')}: "
                                  f"{base64.b32encode(args_dico[arg]).decode()}")
            else:
                args_dico[arg] = utils.input_load_bytes(args_dico[arg].encode(), arg)
        elif SPECS_OTPS[args.algo]["args"][arg]['type'] == int:
            # Check that the parameter is a number if it has to be.
            try:
                args_dico[arg] = int(args_dico[arg])
            except ValueError:
                raise SystemExit(f"The value of {arg} must be a number.")
            except KeyError:
                pass
        elif SPECS_OTPS[args.algo]["args"][arg]['type'] == "module":
            # Parameter associated with a hash function required by OTP operations.
            args_dico[arg] = args_dico[arg].upper()
            if args_dico[arg] == "SHA1":
                args_dico[arg] = SHA1
            elif args_dico[arg] == "SHA256":
                args_dico[arg] = SHA256
            elif args_dico[arg] == "SHA512":
                args_dico[arg] = SHA512
            else:
                raise SystemExit(f"ValueError: Available hash functions are: SHA1, SHA256, SHA512.")

    if args.time:
        timer = timeit.default_timer()

    # OTP code generation according to parameters.
    if args.algo in LIST_ALGO["otp"]["Counter-based One Time Password"]:
        if args.time_step:
            raise SystemExit(f"Error: Argument --time-step incompatible with this algorithm.")
        hotp = HOTP(args_dico["key"], args_dico["length"],
                    args_dico["hash"](), enforce_key_length=False)
        hotp_value = hotp.generate(args_dico["counter"])
        output = hotp_value.decode()
    elif args.algo in LIST_ALGO["otp"]["Time-based One Time Password"]:
        if args.counter:
            raise SystemExit(f"Error: Argument --counter incompatible with this algorithm.")
        totp = TOTP(args_dico["key"], args_dico["length"],
                    args_dico["hash"](), args_dico["time_step"], enforce_key_length=False)
        totp_value = totp.generate(time.time())
        output = totp_value.decode()
    else:
        raise SystemExit(f"Invalid algorithm. Use the --list argument to see the available algorithms.")

    if args.time:
        timer = timeit.default_timer() - timer
        output_sup.append(f"Generation time: {round(timer, 6)} s")

    # Output/results handling.
    total_output = f"{'\n'.join(output_sup)}\nCode: {output}"
    if not args.hide:
        print(total_output)
    if args.copy:
        pyperclip.copy(output)
    if args.output is not False:
        if args.output is None:
            utils.export_file("code_otp.txt", output.encode())
        else:
            utils.export_file(args.output, output.encode())
    if hasattr(args, 'output_all') and args.output_all is not False:
        if args.output_all is None:
            utils.export_file("code_otp_outputs.txt", total_output.encode())
        else:
            utils.export_file(args.output_all, total_output.encode())