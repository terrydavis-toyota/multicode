"""
package/utils.py

This module contains various functions used by the other modules.

Functions:
- export_file: Export the content to a file.
- import_file: Return the encoded content of a file.
- args_cipher_modes: Return a dictionary containing
    all possible specific parameters for the selected encryption algorithm.
- algo_help: Displays specific arguments available for an algorithm.
- input_load_bytes: Convert base64, base32 or base16 (hexadecimal) to binary.
"""

import os
import base64

from package.data import *


def export_file(path, content):
    """ Export the content to a file.

    Returns an error if the operation failed.
    """

    # Content encoding if not already encoded.
    try:
        encoded_content = content.encode()
    except AttributeError:
        encoded_content = content

    # Check if the file already exists at the specified path.
    if os.path.exists(path):
        # Ask the user for confirmation before overwriting an existing file.
        if input(f"\nThe file '{path}' already exists."
                 f"\nDo you want to overwrite it? (N/y) > ") != "y":
            raise SystemExit("No file created.")

    # Try to write the encoded content to the specified file path.
    try:
        with open(path, "wb") as f:
            f.write(encoded_content)
        print(f"File '{path}' successfully written.")
    except Exception as e:
        raise SystemExit(f"Unable to write file: {e}")


def import_file(path):
    """ Return the encoded content of a file. """

    # Attempt to open the file in binary read mode ("rb") and read its content.
    try:
        with open(path, "rb") as f:
            data = f.read()  # Read the entire file content.
    except EnvironmentError as e:
        # If an error occurs during file reading (e.g., file not found), terminate the program with an error message.
        raise SystemExit(f"Failed to read specified file: {e}")

    # Return the file content in binary format.
    return data


def args_cipher_modes(args):
    """
    Return a dictionary containing all possible specific parameters
    for the selected encryption algorithm. Checks for possible command errors.
    """

    args_to_add = {}
    # Check if the algorithm specified in args has specific arguments.
    if "args" in SPECS_CIPHERS[args.algo]:
        # Add arguments for this algorithm to args_to_add.
        for opt in SPECS_CIPHERS[args.algo]["args"]:
            args_to_add[opt] = SPECS_CIPHERS[args.algo]["args"][opt]

        if args.mode:  # If a mode of encryption is specified in args.
            # Check if the algorithm does not support block cipher modes.
            if not "modes" in SPECS_CIPHERS[args.algo]:
                raise SystemExit("The --mode argument is incompatible with this algorithm: "
                                 "\nthis algorithm does not use block cipher modes.")
            # Check if the specified mode is not available for this algorithm.
            elif not args.mode in SPECS_CIPHERS[args.algo]["modes"]:
                raise SystemExit("This block cipher operation mode is not available with this algorithm. "
                                 f"\nUse 'multicode encrypt {args.algo} --list-modes' to see the available modes.")

            # Add the parameters specific to the selected mode to args_to_add.
            for opt in SPECS_CIPHERS[args.algo]["modes"][args.mode]:
                args_to_add[opt] = SPECS_CIPHERS[args.algo]["modes"][args.mode][opt]

        # If a mode is required but not specified.
        elif "modes" in SPECS_CIPHERS[args.algo]:
            raise SystemExit("This algorithm requires the --mode MODE argument as it is a block cipher."
                             f"\nUse 'multicode encrypt {args.algo} --list-modes' to see the available modes.")

    # Return the dictionary containing all possible specific parameters for the selected algorithm.
    return args_to_add


def algo_help(args, command):
    """
    Displays specific arguments available for an algorithm,
    such as an algorithm-specific help command.

    Args:
        args: Parsed arguments containing the algorithm and other options.
        command (str): The type of command being executed (e.g., "hash", "encrypt").
    """

    # Check if the command is "hash". If so, gather specific options for the hashing algorithm.
    if command == "hash":
        args_to_add = {}
        for opt in SPECS_HASHS[args.algo]["args"]:
            args_to_add[opt] = SPECS_HASHS[args.algo]["args"][opt]
    else:
        # For non-hash commands, use the args_cipher_modes function to gather arguments.
        args_to_add = args_cipher_modes(args)

    # Print the usage message for the selected command and algorithm.
    print(f"usage: multicode.py {command} {args.algo} [GLOBAL_OPTION]... [OPTION]..."
          f"\n\n{command[0].upper() + command[1:]} with the {args.algo} algorithm.")

    # No specific options for the algorithm.
    if len(args_to_add) < 1:
        print("\nNo specific options for this algorithm.\n"
              f"Use 'multicode {command} --help' to see all "
              f"available arguments for this algorithm.")
    else:  # Print the specific options for the algorithm.
        print("\n\nSpecific options for this algorithm:")
        for opt in args_to_add:
            # Calculate spacing for formatting the options in the help message.
            esp = 40 - (len(opt) + len(SPECIFIC_OPTIONS[opt]["metavar"]) + 10)
            # Print the option in a formatted way, replacing underscores with hyphens.
            print(f"  --{opt.replace('_', '-')} {SPECIFIC_OPTIONS[opt]['metavar']} ", end="")
            # Split the option description into lines and print each line with proper spacing.
            for line_desc in SPECIFIC_OPTIONS[opt]['description'].split("\n"):
                print(f"{' ' * esp}{line_desc}{args_to_add[opt]['prompt']}")
                esp = 40  # Reset spacing for subsequent lines.
        # Provide a tip on how to access global options in the help message.
        print(f"""\nUse 'multicode {command} --help' to see the global options.""")


def input_load_bytes(data, name_data):
    """
    Convert base64, base32 or base16 (hexadecimal) text to binary.
    Raise an error if the input cannot be converted.

    Args:
        data (str): The encoded string to be converted to binary.
        name_data (str): The name of the data (used for error messages).

    Returns:
        binary_data: The decoded binary data.
    """

    # Try to decode the input as base16 (hexadecimal) first.
    try:
        binary_data = base64.b16decode(data.upper())  # Convert the input to uppercase before decoding.
    except ValueError:
        try:  # If base16 decoding fails, try to decode it as base32.
            binary_data = base64.b32decode(data, casefold=True)
        except ValueError:
            try:  # If base32 decoding fails, try to decode it as base64.
                binary_data = base64.b64decode(data, validate=True)
            except ValueError:
                raise SystemExit(f"The value of {name_data} must be binary "
                                 f"encoded in base64, base32 or hexadecimal.")

    return binary_data
