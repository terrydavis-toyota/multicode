"""
package/hash.py

This file contains the hash function, which is called when the hash command is used.
"""

import importlib
import getpass
import timeit
import base64

import pyperclip

from package.data import *
from package import utils


def hash(args):
    """ Function of the hash command. """

    # Find the algorithm that the user has set as argument and import the corresponding module.
    exceptions_algo_syntax = {"kangarootwelve": "KangarooTwelve", "keccak": "keccak", "tuplehash256": "TupleHash256",
                              "tuplehash128": "TupleHash128", "blake2b": "BLAKE2b", "blake2s": "BLAKE2s",
                              "cshake128": "cSHAKE128", "cshake256": "cSHAKE256", "bcrypt": "bcrypt"}
    if args.algo == "argon2id":
        try:
            from argon2 import PasswordHasher
        except ModuleNotFoundError:
            raise SystemExit("Error: 'argon2-cffi' python module is required for argon2id.")
    elif args.algo == "aes-cmac":
        module = importlib.import_module(f"Cryptodome.Hash.CMAC")
        cipher_module = importlib.import_module(f"Cryptodome.Cipher.AES")
    elif args.algo == "poly1305-aes":
        module = importlib.import_module(f"Cryptodome.Hash.Poly1305")
        cipher_module = importlib.import_module(f"Cryptodome.Cipher.AES")
    elif args.algo == "poly1305-chacha20":
        module = importlib.import_module(f"Cryptodome.Hash.Poly1305")
        cipher_module = importlib.import_module(f"Cryptodome.Cipher.ChaCha20")
    else:
        if args.algo in exceptions_algo_syntax:
            module_algorithm = exceptions_algo_syntax[args.algo]
        else:
            module_algorithm = args.algo.upper().replace('-', '_')
        try:
            module = importlib.import_module(f"Cryptodome.Hash.{module_algorithm}")
        except ModuleNotFoundError:
            try:
                module = getattr(importlib.import_module("Cryptodome.Protocol.KDF"), module_algorithm)
            except (ModuleNotFoundError, AttributeError):
                raise SystemExit(f"Error: Invalid algorithm: '{args.algo}'\n"
                                 "Use the --list option to get the available algorithms.")

    # Checks that all arguments are compatible with the algorithm.
    for arg in [arg for arg in vars(args) if arg in SPECIFIC_OPTIONS and vars(args)[arg] is not False]:
        if "args" not in SPECS_HASHS[args.algo]:
            raise SystemExit(f"The argument {arg} cannot be used with this algorithm.")
        elif arg not in SPECS_HASHS[args.algo]["args"]:
            raise SystemExit(f"The argument {arg} cannot be used with this algorithm.")
    # Defines the input and output encoding functions according to the arguments.
    if args.getpass:
        function_input = getpass.getpass
    else:
        function_input = input
    if args.out_base64:
        function_out = base64.b64encode
    else:
        function_out = base64.b16encode
    # Defines args_dico["data"] (the data to process) according to the chosen input argument.
    args_dico = {}
    if args.checksum:
        args_dico["data"] = utils.import_file(args.checksum)
    elif args.text:
        args_dico["data"] = args.text
    elif args.data:
        args_dico["data"] = utils.input_load_bytes(args.data, "binary input data")
    else:
        args_dico["data"] = function_input("Text to hash: ")
    try:  # Try to encode the data. If it doesn't work, the data is already encoded.
        args_dico["data"] = args_dico["data"].encode()
    except AttributeError:
        pass
    output_sup = []  # List of additional outputs to be displayed.
    if "args" in SPECS_HASHS[args.algo]:
        # For each parameter associated to an algorithm, check if it is in arguments or displays a prompt.
        for arg in SPECS_HASHS[args.algo]["args"]:
            # The parameter is already in arguments.
            if getattr(args, arg) is not False:
                args_dico[arg] = getattr(args, arg)
            # The --default argument blocks the prompt and uses the default value.
            elif args.default and (SPECS_HASHS[args.algo]['args'][arg]['option'] or
                                   SPECS_HASHS[args.algo]['args'][arg]['default'] != ""):
                args_dico[arg] = ""
            else:
                # Prompt the user for the parameter.
                args_dico[arg] = function_input(f"{arg[0].upper() + arg[1:].replace('_', ' ')}"
                                                f"{SPECS_HASHS[args.algo]['args'][arg]['prompt']}: ")
            if SPECS_HASHS[args.algo]['args'][arg]['option'] and args_dico[arg] in ["", None]:
                # The parameter is an option and the value is empty, the parameter is deleted.
                del args_dico[arg]
            elif isinstance(args_dico[arg], str) and SPECS_HASHS[args.algo]['args'][arg]['type'] == str:
                args_dico[arg] = args_dico[arg].encode()
            elif not SPECS_HASHS[args.algo]['args'][arg]['option']:  # The parameter is not an option.
                if SPECS_HASHS[args.algo]['args'][arg]['type'] == bytes:  # The parameter is of type bytes.
                    bytes_to_gen = None
                    if not args.default and args_dico[arg].isdigit():
                        # The value of the parameter is a number, so generate a byte string of this number bits.
                        bytes_to_gen = int(int(args_dico[arg]) / 8)
                    elif args_dico[arg] in ["", None]:
                        # The value of the parameter is empty, so generate a byte string of the default length.
                        bytes_to_gen = SPECS_HASHS[args.algo]['args'][arg]['default']
                    if bytes_to_gen:
                        from Cryptodome.Random import get_random_bytes
                        args_dico[arg] = get_random_bytes(bytes_to_gen)
                        output_sup.append(f"{arg[0].upper() + arg[1:].replace('_', ' ')}: "
                                          f"{function_out(args_dico[arg]).decode()}")
                        continue
                elif args_dico[arg] in ["", None]:
                    # The type of the parameter is not in bytes but, it is empty, so load the default value.
                    args_dico[arg] = SPECS_HASHS[args.algo]['args'][arg]['default']
                # The parameter is an integer.
                if SPECS_HASHS[args.algo]['args'][arg]['type'] == int:
                    try:
                        args_dico[arg] = int(args_dico[arg])
                    except ValueError:
                        raise SystemExit(f"The value of {arg} must be a number.")
                # The parameter must be in bytes, so convert the hexadecimal, base32 or base64 value to bytes.
                elif SPECS_HASHS[args.algo]['args'][arg]['type'] == bytes:
                    args_dico[arg] = utils.input_load_bytes(args_dico[arg], "binary input data")
                # The parameter is a module.
                elif SPECS_HASHS[args.algo]['args'][arg]['type'] == "module":
                    if args_dico[arg] in exceptions_algo_syntax:
                        args_dico[arg] = exceptions_algo_syntax[args_dico[arg]]
                    else:
                        args_dico[arg] = args_dico[arg].upper().replace('-', '_')
                    try:
                        args_dico[arg] = importlib.import_module(f"Cryptodome.Hash.{args_dico[arg]}")
                    except ModuleNotFoundError:
                        raise SystemExit(f"Invalid algorithm. Use the --list argument to see the available algorithms.")

    if args.time:
        timer = timeit.default_timer()
    try:
        if "type" in SPECS_HASHS[args.algo] and SPECS_HASHS[args.algo]["type"] == "XOF":
            hash_object = module.new(**{i: args_dico[i] for i in args_dico if i != "digest_bits"})
            hash_object = hash_object.read(int(args_dico["digest_bits"]/8))
            output = function_out(hash_object).decode()
        elif "type" in SPECS_HASHS[args.algo] and SPECS_HASHS[args.algo]["type"] == "KDF":
            if "digest_bits" in args_dico:
                args_dico["dkLen"] = int(args_dico["digest_bits"]/8)
                del args_dico["digest_bits"]
            if "hash" in args_dico and args.algo == "pbkdf2":
                args_dico["hmac_hash_module"] = args_dico["hash"]
                del args_dico["hash"]
            if isinstance(args_dico["data"], bytes):
                args_dico["password"] = args_dico["data"].decode()
            else:
                args_dico["password"] = str(args_dico["data"])
            del args_dico["data"]
            hash_object = module(**{i: args_dico[i] for i in args_dico})
            if args.algo == "bcrypt":
                output = hash_object.decode()
                if args.verify:
                    from Cryptodome.Protocol.KDF import bcrypt_check
                    try:
                        print(args_dico["password"], args.verify)
                        bcrypt_check(args_dico["password"], args.verify)
                        output_sup.append("Correct password")
                    except ValueError:
                        output_sup.append("Incorrect password")
            elif args.algo == "pbkdf2":
                output = function_out(hash_object).decode()
                if args.verify:
                    try:
                        assert output == args.verify
                        output_sup.append("Correct password")
                    except AssertionError:
                        output_sup.append("Incorrect password")
            else:
                output = function_out(hash_object).decode()
        else:
            if "hash" in args_dico and args.algo == "hmac":
                args_dico["digestmod"] = args_dico["hash"]
                del args_dico["hash"]
            elif "digest_bits" in args_dico and args.algo == "sha512":
                args_dico["truncate"] = str(args_dico["digest_bits"])
                del args_dico["digest_bits"]
            elif "digest_bits" in args_dico and args.algo.startswith("kmac"):
                args_dico["mac_len"] = args_dico["digest_bits"]
                del args_dico["digest_bits"]
            if args.algo.startswith("poly1305"):
                args_dico["cipher"] = cipher_module
            elif args.algo == "aes-cmac":
                hash_object = module.new(args_dico["key"], ciphermod=cipher_module)
                hash_object.update(args_dico["data"])
                output = function_out(hash_object.digest()).decode()
                if args.verify:
                    try:
                        hash_object.verify(utils.input_load_bytes(args.verify, "mac to check"))
                        output_sup.append("The data is authentic")
                    except ValueError:
                        output_sup.append("The message or the key is wrong")
            elif args.algo == "argon2id":
                args_dico["time_cost"] = args_dico["iterations"]
                del args_dico["iterations"]
                hash_object = PasswordHasher(**{i: args_dico[i] for i in args_dico if i != "data"})
                output = hash_object.hash(args_dico["data"])
                if args.verify:
                    try:
                        hash_object.verify(args.verify, args_dico["data"])
                        output_sup.append("The data is authentic")
                    except Exception:
                        output_sup.append("The message or the key is wrong")
            else:
                hash_object = module.new(**{i: args_dico[i] for i in args_dico if i != "data"})
                hash_object.update(args_dico["data"])
                output = function_out(hash_object.digest()).decode()
                if args.verify:
                    if output == args.verify:
                        output_sup.append("The data is authentic")
                    else:
                        output_sup.append("The message or the key is wrong")
    except (ValueError, AttributeError) as e:
        raise SystemExit(f"Invalid value: {e}")
    if args.time:
        timer = timeit.default_timer() - timer
        output_sup.append(f"Generation time: {round(timer, 6)} s")

    # Output/results handling.
    total_output = f"{'\n'.join(output_sup)} \nHash: {output}"
    if not args.hide:
        print(f"{total_output}")
    if args.copy:
        pyperclip.copy(output)
    if args.output is not False:
        if args.output is None:
            utils.export_file("hash_output.txt", output.encode())
        else:
            utils.export_file(args.output, output.encode())
    if hasattr(args, 'output_all') and args.output_all is not False:
        if args.output_all is None:
            utils.export_file("hash_outputs.txt", total_output.encode())
        else:
            utils.export_file(args.output_all, total_output.encode())