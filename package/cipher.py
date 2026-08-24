"""
package/cipher.py

This file contains the cipher function, which is called when the encrypt or decrypt command is used.
"""

import importlib
import getpass
import timeit
import base64

import pyperclip

from package.data import *
from package import utils
from package import caesar


def cipher(args, command):
    """ Function of the encrypt and decrypt command. """

    if args.algo == "hex":  # The hex encoding is an alias to the base16 encoding.
        args.algo = "base16"
    if args.algo in LIST_ALGO["cipher"]["Encodings"]:  # If the algorithm is an encoding, adapt the commands.
        if command == "encrypt":
            command = "encode"
        elif command == "decrypt":
            command = "decode"
    try:  # Import the module associated with the algorithm.
        module = importlib.import_module(SPECS_CIPHERS[args.algo]["module"])
    except (ModuleNotFoundError, KeyError):
        raise SystemExit(f"Error: Invalid algorithm: '{args.algo}'\n"
                         "Use the --list option to get the available algorithms.")

    # Checks that all arguments are compatible with the algorithm.
    for arg in [arg for arg in vars(args) if arg in SPECIFIC_OPTIONS and vars(args)[arg] is not False]:
        if "args" not in SPECS_CIPHERS[args.algo]:
            raise SystemExit(f"The argument {arg} cannot be used with this algorithm.")
        elif arg not in SPECS_CIPHERS[args.algo]["args"]:
            if args.mode:
                if arg not in SPECS_CIPHERS[args.algo]["modes"][args.mode]:
                    raise SystemExit(f"The argument {arg} cannot be used with this algorithm.")
            else:
                raise SystemExit(f"The argument {arg} cannot be used with this algorithm.")
    if "rsa" in args.algo:
        if not args.keyfile:
            raise SystemExit(f"You need to import the RSA key from a file using --keyfile KEY_FILE.")
    # Obtain a dictionary of arguments for this algorithm and check for errors for block cipher modes.
    args_to_add = utils.args_cipher_modes(args)
    # Defines the input method and output encoding functions according to the arguments.
    if args.getpass:
        function_input = getpass.getpass
    else:
        function_input = input
    if args.out_base64:
        function_out = base64.b64encode
    else:
        function_out = base64.b16encode
    # Defines args_dico["data"] (the data to process) according to the chosen input method.
    args_dico = {}
    if args.file:
        args_dico["data"] = utils.import_file(args.file)
    elif args.text:
        args_dico["data"] = args.text
    elif args.data:
        if args.algo in LIST_ALGO["cipher"]["Encodings"]:
            args_dico["data"] = args.data
        else:
            args_dico["data"] = utils.input_load_bytes(args.data, "binary input data")
    elif command == "encrypt":
        args_dico["data"] = function_input(f"Text to {command}: ")
    else:
        args_dico["data"] = function_input(f"Data to {command}: ")
        if args.algo != "caesar":
            if args.algo in LIST_ALGO["cipher"]["Encodings"]:
                args_dico["data"] = args_dico["data"]
            else:
                args_dico["data"] = utils.input_load_bytes(args_dico["data"], "cipherdata")
    output_sup = []  # List of additional outputs to be displayed.
    if "args" in SPECS_CIPHERS[args.algo]:
        # For each parameter associated to the algorithm, check if it is in arguments or displays a prompt.
        for arg in args_to_add:
            if getattr(args, arg) is not False:  # The parameter is already in arguments.
                args_dico[arg] = getattr(args, arg)
            elif args_to_add[arg]['type'] == bytes and command == "decrypt":
                if args_to_add[arg]['option']:
                    args_dico[arg] = function_input(f"{arg[0].upper() + arg[1:].replace('_', ' ')} (optional): ")
                else:
                    args_dico[arg] = function_input(f"{arg[0].upper() + arg[1:].replace('_', ' ')}: ")
            # The --default argument blocks the prompt and uses the default value.
            elif args.default and (args_to_add[arg]['option'] or
                                   args_to_add[arg]['default'] != ""):
                args_dico[arg] = ""
            elif args_to_add[arg]['type'] != bytes or command != "decrypt":  # Prompt the user for the parameter.
                if arg == "mac_len" and command == "decrypt":
                    args_dico[arg] = None
                else:
                    args_dico[arg] = function_input(f"{arg[0].upper() + arg[1:].replace('_', ' ')}"
                                                    f"{args_to_add[arg]['prompt']}: ")
            if args_to_add[arg]['option'] and args_dico[arg] in ["", None]:
                # The parameter is an option and the value is empty, the parameter is deleted.
                del args_dico[arg]
                continue
            else:
                if args_to_add[arg]['type'] == bytes:  # The parameter is of type bytes.
                    bytes_to_gen = None
                    if not args.default and args_dico[arg].isdigit():
                        # The value of the parameter is a number, so generate a byte string of this number bits.
                        bytes_to_gen = int(int(args_dico[arg]) / 8)
                    elif args_dico[arg] in ["", None] and not args_to_add[arg]['option']:
                        # The value of the parameter is empty, so generate a byte string of the default length.
                        bytes_to_gen = args_to_add[arg]['default']
                    if bytes_to_gen:
                        from Cryptodome.Random import get_random_bytes
                        args_dico[arg] = get_random_bytes(bytes_to_gen)
                        output_sup.append(f"{arg[0].upper() + arg[1:].replace('_', ' ')}: "
                                          f"{function_out(args_dico[arg]).decode()}")
                        continue
                elif args_dico[arg] in ["", None] and not args_to_add[arg]['option']:
                    # The type of the parameter is not in bytes but it is empty, so load the default value.
                    args_dico[arg] = args_to_add[arg]['default']
                    continue
            # The parameter is an integer.
            if args_to_add[arg]['type'] == int:
                try:
                    args_dico[arg] = int(args_dico[arg])
                except ValueError:
                    raise SystemExit(f"The value of {arg} must be a number.")
            # The parameter must be in bytes, so convert the hexadecimal, base64 or base32 value to bytes.
            elif args_to_add[arg]['type'] == bytes:
                args_dico[arg] = utils.input_load_bytes(args_dico[arg], arg)
            # The parameter is a string.
            elif args_to_add[arg]['type'] == str:
                try:
                    args_dico[arg] = args_dico[arg].encode()
                except AttributeError:
                    pass

    if args.time:
        timer = timeit.default_timer()
    try:
        if args.algo in LIST_ALGO["cipher"]["Encodings"]:
            try:
                args_dico["data"] = args_dico["data"].encode()
            except AttributeError:
                pass
            # Call the encoding functions (b16encode, b16decode, etc...)
            module = getattr(module, "b" + args.algo[-2:] + command)
            encoded_output = module(args_dico["data"])
            try:
                decoded_output = encoded_output.decode()
            except (AttributeError, UnicodeDecodeError):
                decoded_output = function_out(encoded_output).decode()
        else:
            if args.mode and args.algo != "serpent":  # Add a "mode" argument to the encryption object.
                args_dico["mode"] = getattr(module, f"MODE_{args.mode.upper()}")
                if "mac_len" in args_dico:
                    args_dico["mac_len"] = int(args_dico["mac_len"] / 8)
            if args.algo == "3des":
                try:
                    args_dico["key"] = module.adjust_key_parity(args_dico["key"])
                except ValueError as e:
                    raise SystemExit(f"Invalid value: {e}")
            if args.algo != "caesar":
                if args.algo == "fernet":
                    args_dico["key"] = base64.b64encode(args_dico["key"])
                    cipher = module.Fernet(args_dico["key"])
                elif args.algo != "serpent" and "rsa" not in args.algo:
                    cipher = module.new(**{i: args_dico[i] for i in args_dico if i not in ["data"]})
            if command == "encrypt":
                try:
                    args_dico["data"] = args_dico["data"].encode()
                except (AttributeError, UnicodeDecodeError):
                    pass
                if "rsa" in args.algo:
                    from Cryptodome.PublicKey import RSA
                    passphrase = getpass.getpass("file key passphrase ([EMPTY] if none):")
                    if not passphrase:
                        passphrase = None
                    try:
                        public_key = RSA.importKey(utils.import_file(args.keyfile), passphrase=passphrase)
                    except ValueError:
                        raise SystemExit("Invalid public key: Incorrect format or encrypted key.")
                    cipher = module.new(public_key)
                    encoded_output = cipher.encrypt(args_dico["data"])
                else:
                    if args.mode and MODE_SPECS[args.mode]["padding"] and args.algo != "serpent":  # Padding of data if needed.
                        from Cryptodome.Util import Padding
                        args_dico["data"] = Padding.pad(args_dico["data"], module.block_size)
                        encoded_output = cipher.encrypt(args_dico["data"])
                    elif args.algo == "chacha20poly1305" or args.mode and MODE_SPECS[args.mode]["mac"]:
                        encoded_output, tag = cipher.encrypt_and_digest(args_dico["data"])
                        output_sup.append(f"Tag: {function_out(tag).decode()}")
                    elif args.algo == "caesar":
                        encoded_output = caesar.caesar(args_dico["data"], args_dico["key"])
                    elif args.algo == "serpent":
                        if args.mode == "ecb":
                            serpent = module.Serpent(args_dico["key"])
                            encoded_output = module.Serpent.encrypt(serpent, args_dico["data"])
                        else:
                            encoded_output = module.serpent_cbc_encrypt(args_dico["key"], args_dico["data"], iv=args_dico["iv"])
                            encoded_output = bytes(bytearray(encoded_output)[16:])  # Remove IV.
                    else:
                        encoded_output = cipher.encrypt(args_dico["data"])
                        if args.algo == "fernet":
                            encoded_output = base64.b16encode(base64.b85decode(encoded_output))
            elif command == "decrypt":
                if "rsa" in args.algo:
                    from Cryptodome.PublicKey import RSA
                    passphrase = getpass.getpass("file key passphrase ([EMPTY] if none):")
                    if not passphrase:
                        passphrase = None
                    try:
                        private_key = RSA.importKey(utils.import_file(args.keyfile), passphrase=passphrase)
                    except ValueError:
                        raise SystemExit("Invalid private key: Incorrect format or encrypted key.")
                    cipher = module.new(private_key)
                    if args.algo == "rsa-pkcs1.5":
                        encoded_output = cipher.decrypt(args_dico["data"], sentinel=False)
                    else:
                        encoded_output = cipher.decrypt(args_dico["data"])
                else:
                    if args.mode and MODE_SPECS[args.mode]["padding"] and args.algo != "serpent":  # Unpadding of data if needed.
                        from Cryptodome.Util import Padding
                        encoded_output = Padding.unpad(cipher.decrypt(args_dico["data"]), module.block_size)
                    elif args.algo == "chacha20poly1305" or args.mode and MODE_SPECS[args.mode]["mac"]:
                        tag = function_input("Tag (TAG/empty to pass MAC check): ")
                        if tag:
                            tag = utils.input_load_bytes(tag, "tag")
                            try:
                                encoded_output = cipher.decrypt_and_verify(args_dico["data"], tag)
                                output_sup.append("The MAC is correct.")
                            except ValueError:
                                output_sup.append("The MAC is invalid: the authenticity check has failed.")
                        else:
                            encoded_output = cipher.decrypt(args_dico["data"])
                            output_sup.append("MAC Authenticity could not be verified.")
                    elif args.algo == "caesar":
                        encoded_output = caesar.caesar(args_dico["data"], -args_dico["key"])
                    elif args.algo == "fernet":
                        args_dico["data"] = base64.b85encode(args_dico["data"])
                        encoded_output = cipher.decrypt(args_dico["data"])
                    elif args.algo == "serpent":
                        if args.mode == "ecb":
                            serpent = module.Serpent(args_dico["key"])
                            encoded_output = module.Serpent.decrypt(serpent, args_dico["data"])
                        else:
                            # Add IV to Ciphertext.
                            encoded_output = module.serpent_cbc_decrypt(args_dico["key"], data=args_dico["iv"]+args_dico["data"])
                    else:
                        encoded_output = cipher.decrypt(args_dico["data"])

    except ValueError as e:
        raise SystemExit(f"Invalid value: {e}")
    if args.time:
        timer = timeit.default_timer() - timer
        output_sup.append(f"Generation time: {round(timer, 6)} s")

    # Output/results handling.
    if encoded_output:
        try:
            decoded_output = encoded_output.decode()
        except (AttributeError, UnicodeDecodeError):
            decoded_output = function_out(encoded_output).decode()
        except UnboundLocalError:
            encoded_output, decoded_output = False, False
    total_output = f"{'\n'.join(output_sup)}\n"
    if command == "encrypt":
        total_output += f"Ciphertext: {decoded_output}"
    elif command == "decrypt":
        total_output += f"Plaintext: {decoded_output}"
    else:
        total_output += f"{command[0].upper() + command[1:] + 'd'}: {decoded_output}"
    if not args.hide:
        print(total_output)
    if args.copy and decoded_output:
        pyperclip.copy(decoded_output)
    if args.output is not False:
        if args.output is None:
            utils.export_file("cipher_output.txt", decoded_output.encode())
        else:
            utils.export_file(args.output, decoded_output.encode())
    if hasattr(args, 'output_all') and args.output_all is not False:
        if args.output_all is None:
            utils.export_file("cipher_outputs.txt", total_output.encode())
        else:
            utils.export_file(args.output_all, total_output.encode())