#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK

"""
Multicode is a powerful yet user-friendly cryptography toolkit.

multicode.py

This file is the python file to execute, it configures the CLI interface with argparse.
"""

import sys
import argparse

from tabulate import tabulate

from package.data import *
from package import utils
from package import hash
from package import key
from package import signature
from package import cipher
from package import otp
from package import padding


class CustomGlobalArgumentParser(argparse.ArgumentParser):
    """ Modification of ArgumentParser to customize the global help message. """

    def format_help(self):
        return """Usage: multicode.py COMMAND ALGORITHM [OPTION]...

An all-in-one command-line tool for using cryptography.

Commands:
   encrypt, e         Encrypt or encode
   decrypt, d         Decrypt or decode
   signature, s       Generate or verify a digital signature
   hash, h            hash, MAC and key derivation functions
   key, k             Generate asymmetric keys and random binary keys
   otp                Generate OTP codes
   padding            Fill the data to reach a multiple of block in bits

Global options:
   --help, -h         Show command help
   --list, -l         List the algorithms available for a command
   --algo-help        Help for some algorithms with specific options
   --output, -o [FILE]  Export the main output to a file
   --output-all [FILE]  Export all outputs to a file
   --copy, -c         Copy the main output to the clipboard
   --hide, -H         Don't display the output in the terminal
   --default, -d      Don't ask for any parameters and use the default values
   --time, -T         Show how long the calculation took
   --out-base64, -a   Output binary result in base64 instead of hexadecimal
   
Examples of commands are provided in the command help.
You can omit any algorithm parameters to be prompted for them.
"""


def main():
    # Definition of the main parser, subparsers (commands), global options.
    main_parser = CustomGlobalArgumentParser(usage="multicode.py [GLOBAL_OPTION] COMMAND ALGORITHM [COMMAND_OPTION]...")
    subparsers = main_parser.add_subparsers(dest="command", required=True, parser_class=argparse.ArgumentParser)
    main_parser.add_argument("-v", "--version", action='version', version='multicode ' + VERSION_MULTICODE)
    if len(sys.argv) == 1:
        # Displays the help when the program is started without arguments.
        main_parser.print_help(sys.stderr)
        sys.exit(1)
    # Set the parent parser. A shortcut to assign the same arguments to several parsers.
    basic_parser = argparse.ArgumentParser(add_help=False)
    basic_parser.add_argument("--output", "-o", nargs="?",
                              const=None, default=False, metavar="FILE", help="Export output to file")
    basic_parser.add_argument("--out-base64", "-a", action="store_true", help="Output in base64")
    basic_parser.add_argument("--copy", "-c", action="store_true", help="Copy output to clipboard")
    basic_parser.add_argument("--hide", "-H", action="store_true", help="Hide output")
    basic_parser.add_argument("--time", "-T", action="store_true", help="Show execution time")
    basic_parser.add_argument("--default", "-d", action="store_true", help="Use default values")

    # Definition of arguments and options for the encryption AND decryption command.
    cipher_parent = argparse.ArgumentParser()
    cipher_parent._positionals.title = 'Positional arguments'
    cipher_parent._optionals.title = 'Optional arguments'
    cipher_parent.add_argument("algo", nargs="?", metavar="ALGORITHM",
                                help="Use --list to get the available algorithms")
    cipher_parent.add_argument("--list", "-l", action="store_true", help="List available algorithms")
    cipher_parent.add_argument("--mode", "-m", metavar="MODE", default=False,
                                help="Operation mode of the block cipher")
    key_input = cipher_parent.add_mutually_exclusive_group(required=False)
    key_input.add_argument("--key", "-k", metavar="KEY", default=False, help="The key")
    input_arg = cipher_parent.add_mutually_exclusive_group(required=False)
    input_arg.add_argument("--text", "-t", metavar="TEXT", default=False, help="Text to be encrypted or encoded")
    input_arg.add_argument("--file", "-f", metavar="FILE", help="File to be encrypted or encoded")
    input_arg.add_argument("--data", metavar="BINARY_DATA", default=False,
                           help="Binary data to encrypt. Encoded in base32, base64 or hexa")
    cipher_parent.add_argument("--getpass", "-g", action="store_true",
                                help="Use the secure getpass function for prompts")
    key_input.add_argument("--keyfile", metavar="KEY_FILE", default=False,
                           help="Use the content of a file as the key")
    cipher_parent.add_argument("--algo-help", help="Show specific help for an algorithm", action="store_true")
    cipher_parent.add_argument("--list-modes", help="List the available operation modes for an algorithm",
                                action="store_true")
    for arg in ["--nonce", "--iv", "--mac-len", "--segment-size", "--initial-value"]:  # Specific options for specifics algorithms.
        cipher_parent.add_argument(arg, default=False, help=argparse.SUPPRESS)

    encrypt_parser = subparsers.add_parser("encrypt", parents=[basic_parser, cipher_parent], aliases=["e"], add_help=False,
                                           formatter_class=argparse.RawTextHelpFormatter,
                                           usage="multicode.py e ALGORITHM [-k KEY] [-t TEXT] [OPTION]...",
                                           description="Encrypt or encode text or file.",
                                           epilog="Examples:\n  mc e aes --mode gcm -c --file file.txt --output result.enc\n\n"
                                                  "  Encrypts the contents of file.txt with AES-GCM \n"
                                                  "  and copies the result to the clipboard and to file.enc")
    decrypt_parser = subparsers.add_parser("decrypt", parents=[basic_parser, cipher_parent], aliases=["d"], add_help=False,
                                           formatter_class=argparse.RawTextHelpFormatter,
                                           usage="multicode.py d ALGORITHM [-k KEY] [-t TEXT] [OPTION]...",
                                           description="Decrypt or decode text or file.",
                                           epilog="Example:\n  mc d aes --mode gcm -c --file file.enc --output result.txt\n\n"
                                                  "  Decrypts the contents of file.enc with AES-GCM \n"
                                                  "  and writes the result to result.txt and the clipboard.")

    # Definition of arguments and options for the hash command.
    hash_parser = subparsers.add_parser("hash", parents=[basic_parser], aliases=["h"],
                                        formatter_class=argparse.RawTextHelpFormatter,
                                        usage="multicode.py h ALGORITHM "
                                                              "[-t INPUT_TEXT] [OPTION]...",
                                        description="Hash Functions, Key Derivation Functions, "
                                                    "MACs and Extensible-Output Functions.",
                                        epilog="Example:\n  multicode h sha2-256 -t 'Etaji 56' -c\n\n"
                                               "  Hash the text 'Etaji 56' with sha2_256 and copy the result.")
    hash_parser._positionals.title = 'Positional arguments'
    hash_parser._optionals.title = 'Optional arguments'
    hash_parser.add_argument("algo", nargs="?", metavar="ALGORITHM", help="Use --list to get the available algorithms")
    hash_parser.add_argument("--list", "-l", action="store_true", help="List available algorithms")
    input_arg_exclusive = hash_parser.add_mutually_exclusive_group(required=False)
    input_arg_exclusive.add_argument("--text", "-t", metavar="INPUT_TEXT", default=False, help="The input text")
    input_arg_exclusive.add_argument("--data", metavar="BINARY_DATA", default=False,
                                     help="Binary data in input. Encoded in base32, base64 or hexa")
    hash_parser.add_argument("--verify", metavar="HASH", default=False, help="Check if a hash matches the input")
    hash_parser.add_argument("--getpass", "-g", action="store_true",
                             help="Use the secure getpass function for prompts")
    hash_parser.add_argument("--checksum", "-f", metavar="FILE", help="Get the checksum of a file")
    hash_parser.add_argument("--algo-help", help="Show specific help for an algorithm", action="store_true")
    for arg in ["--key", "--digest-bits", "--hash", "--custom", "--nonce", "--salt", "--number-keys", "--count", "--cost", "--iterations", "--memory-cost", "--parallelism", "--hash-len", "--salt-len"]:
        hash_parser.add_argument(arg, default=False, help=argparse.SUPPRESS)

    # Definition of arguments and options for the key command.
    key_parser = subparsers.add_parser("key", parents=[basic_parser], aliases=["k"],
                                       formatter_class=argparse.RawTextHelpFormatter,
                                       usage="multicode.py k [ALGORITHM] [BITS] [OPTION]...",
                                       description="Generate keys",
                                       epilog="Examples:\n  multicode k\n"
                                              "  Generate a random 128-bit key\n\n"
                                              "  multicode k rsa 4096 -o key.pem --openssh\n"
                                              "  Generate a 4096 bits rsa key with the OpenSSH format public key and export it to a file\n")
    key_parser._positionals.title = 'Positional arguments'
    key_parser._optionals.title = 'Optional arguments'
    key_parser.add_argument("algo", nargs="?", metavar="ALGORITHM", default=False,
                            help="Optional public key algorithm. Use the --list command to see them.\n"
                                 "If no algorithm is specified, a random set of bytes will be generated")
    key_parser.add_argument("bits", metavar="NUMBITS", default=False, nargs="?", type=int,
                            help="Optional: number of bits in the key.\n"
                                 "Without the argument, the recommended value will be used")
    key_parser.add_argument("--list", "-l", action="store_true", help="List available algorithms")
    key_parser.add_argument("--bytes", "-b", metavar="NUMBYTES", default=False, type=int,
                            help="Number of bytes in the key. not allowed with NUMBITS argument")
    key_parser.add_argument("--passphrase", "-p",
                            help="The passphrase to protect the private key (pkcs1 is used)")
    key_parser.add_argument("--curve", metavar="CURVE",
                            help="eliptic curve for the ecc algorithm (Default: ed25519)\n"
                                 "pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html")
    key_parser.add_argument("--output-public", "-u", metavar="FILE", default=False, nargs="?",
                            help="Export public key to a file")
    key_parser.add_argument("--public", metavar="FILE_PRIVATEKEY", default=False,
                            help="Calculate the public key corresponding to the private key")
    key_parser.add_argument("--openssh", action="store_true",
                            help="The public key will be encoded in OpenSSH format instead of PEM")

    # Definition of arguments and options for the signature command.
    signature_parser = subparsers.add_parser("signature", parents=[basic_parser], aliases=["s"],
                                             formatter_class=argparse.RawTextHelpFormatter,
                                             usage="multicode.py s ALGORITHM KEY_FILE --sign|--verify SIGNATURE"
                                                   " [-t MESSAGE] [OPTION]...",
                                             description="Create or verify cryptographic signatures.",
                                             epilog="Examples:\n  multicode s dss privatekey.pem --sign -t order1\n"
                                                    "  Generates an ecc dss signature of 'order1' with the private key"
                                                    " of the file 'privatekey.pem'\n\n  "
                                                    "multicode s dss publickey.pem --verify SIGNATURE --t order1\n  "
                                                    "Verifies the signature of the order1 message with the public key")
    signature_parser._positionals.title = 'Positional arguments'
    signature_parser._optionals.title = 'Optional arguments'
    signature_parser.add_argument("algo", nargs="?", metavar="ALGORITHM",
                                  help="Use --list to get the available algorithms")
    signature_parser.add_argument("key", nargs="?", metavar="KEY_FILE",
                                  help="Private or public key file")
    signature_parser.add_argument("--list", "-l", action="store_true", help="List available algorithms")
    sign_command_arg = signature_parser.add_mutually_exclusive_group(required=False)
    sign_command_arg.add_argument("--sign", "-s", action="store_true", help="Signing a message with a private key")
    sign_command_arg.add_argument("--verify", "-v", metavar="SIGNATURE",
                                  help="Verify the authenticity of a signature with the public key")
    input_arg = signature_parser.add_mutually_exclusive_group(required=False)
    input_arg.add_argument("--text", "-t", metavar="MESSAGE", default=False, help="Text signed or to be signed")
    input_arg.add_argument("--file", "-f", metavar="FILE", help="File signed or to be signed. "
                                                                "Use the file data as a message")
    input_arg.add_argument("--data", metavar="BINARY_DATA", default=False,
                           help="Binary data signed or to be signed. Encoded in base32, base64 or hexa")
    signature_parser.add_argument("--passphrase", "-p", help="The passphrase that protects the private key.")

    # Definition of arguments and options for the otp command.
    otp_parser = subparsers.add_parser("otp", parents=[basic_parser], aliases=["otp"],
                                       formatter_class=argparse.RawTextHelpFormatter,
                                       usage="multicode.py otp [ALGORITHM] [OPTION]...",
                                       description="Generate OTP authentication codes",
                                       epilog="Example:\n  mc otp totp --default\n"
                                              "  Generate a TOTP key with default values.\n\n"
                                              "  mc otp totp --default --key OQYTST4IG65C7X24QK6ROSANG35S23BK\n"
                                              "  Obtain the temporary OTP code with the specified key.")
    otp_parser._positionals.title = 'Positional arguments'
    otp_parser._optionals.title = 'Optional arguments'
    otp_parser.add_argument("algo", nargs="?", metavar="ALGORITHM", help="Use --list to get the available algorithms")
    otp_parser.add_argument("--list", "-l", action="store_true", help="List available algorithms")
    otp_parser.add_argument("--key", "-k", metavar="KEY", default=False, help="Secret key in base32, hexa or base64.")
    otp_parser.add_argument("--hash", metavar="HASH_FUNCTION", default=False, help="The hash function to be used")
    otp_parser.add_argument("--length", "-L", metavar="NB_DIGITS", default=False,
                            help="Number of digits per one time password")
    otp_parser.add_argument("--counter", metavar="COUNTER", default=False,
                            help="The counter value used to generate the HOTP one-time password")
    otp_parser.add_argument("--time-step", metavar="SECONDS", default=False,
                            help="The number of seconds between each TOTP change")
    otp_parser.add_argument("--getpass", "-g", action="store_true",
                            help="Use the secure getpass function for prompts")

    # Definition of arguments and options for the padding command.
    padding_parser = subparsers.add_parser("padding", parents=[basic_parser],
                                           formatter_class=argparse.RawTextHelpFormatter,
                                           usage="multicode.py padding [ALGORITHM] --text TEXT|--data BINARY_DATA "
                                                 "[--unpad] [--block-size BLOCK_BITS] [OPTION]..",
                                           description="Fill the data to reach a multiple of block in bits",
                                           epilog="Example:\n  mc padding pkcs7 --data 0A1B --block-size 128\n"
                                                  "  Complete the 8-bit binary data to reach 128 bits.\n\n"
                                                  "  mc padding pkcs7 --data 0A1B0E0E0E0E0E0E0E0E0E0E0E0E0E0E --default --unpad\n"
                                                  "  Get 8-bit binary data without added padding.")
    padding_parser._positionals.title = 'Positional arguments'
    padding_parser._optionals.title = 'Optional arguments'
    padding_parser.add_argument("algo", nargs="?", metavar="ALGORITHM", help="Use --list to get the available algorithms")
    padding_parser.add_argument("--list", "-l", action="store_true", help="List available algorithms")
    exclusive_input = padding_parser.add_mutually_exclusive_group(required=True)
    exclusive_input.add_argument("--text", metavar="TEXT", default=False,
                                 help="Input text. Incompatible with --unpad")
    exclusive_input.add_argument("--data", metavar="BINARY_DATA", default=False,
                                 help="Binary data to padd or unpadd. Encoded in base32, base64 or hexa")
    padding_parser.add_argument("--unpad", default=False, action="store_true",
                                help="Unpadd data instead of padding it")
    padding_parser.add_argument("--block-size", metavar="BITS_BLOCK_SIZE", help="Block size in bits")
    padding_parser.add_argument("--getpass", "-g", action="store_true",
                                help="Use the secure getpass function for prompts")

    args = main_parser.parse_args()  # Parse CLI args with argparse.

    if getattr(args, "mode", None):
        args.mode = args.mode.lower()
    if getattr(args, "algo", None):
        args.algo = args.algo.lower()

    for a in ALIASES_CMD:  # Command aliases.
        if a == args.command:
            args.command = ALIASES_CMD[args.command]

    if args.list:  # --list/-l option: list available algorithms for a command.
        print(tabulate(LIST_ALGO[args.command], headers="keys"))
        if args.command == "encrypt" or args.command == "decrypt":
            print("\nSome algorithms require a mode of operation because they are block ciphers."
                  "\nIn this case use --mode MODE. To know which modes are available for an algorithm,"
                  "\nuse the --list-modes option.")
        sys.exit(1)

    if not args.algo and args.command != "key":  # ALGORITHME argument is not an option.
        main_parser.error("the following arguments are required: ALGORITHM\n"
                          "Use --list to show available algorithms.")

    match args.command:  # Using Functions from Other Modules Based on the Command.
        case "encrypt" | "decrypt":
            if args.algo_help:
                utils.algo_help(args, args.command)
            elif args.list_modes:
                if "modes" not in SPECS_CIPHERS[args.algo]:
                    print("This algorithm does not require an operation mode (--mode), as it is not a block cipher.")
                else:
                    print("This algorithm is a block cipher, it requires an operation mode."
                          "\nThe --mode MODE option is then required with this algorithm."
                          "\n\nThe available modes for this algorithm:")
                    print(*SPECS_CIPHERS[args.algo]["modes"].keys(), sep="\n")
                    print("\nUse the --algo-help option to view algorithm-specific arguments.")
            else:
                cipher.cipher(args, args.command)

        case "hash":
            hash.hash(args)
        case "key":
            key.key(args)
        case "signature":
            signature.signature(args)
        case "otp":
            otp.otp(args)
        case "padding":
            padding.padd(args)


if __name__ == '__main__':
    main()