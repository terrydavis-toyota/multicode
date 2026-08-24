"""
package/caesar.py

Caesar algorithm for cipher command.
"""

def caesar(text, shift):
    """
    Encrypts or decrypts a given text using the Caesar cipher.

    Args:
    text: The text to be encrypted or decrypted.
    shift: The number of positions to shift the letters in the alphabet.

    Returns:
    The encrypted or decrypted text.
    """

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""

    if isinstance(text, bytes):
        try:
            text = text.decode()
        except ValueError:
            raise SystemExit("Error: you can't use --data with caesar.")
    for char in text.upper():
        if char in alphabet:
            index = (alphabet.find(char) + shift) % 26
            result += alphabet[index]
        elif char == " ":
            result += char
        else:
            raise SystemExit("ValueError: Cesar algorithm only supports text.")
    result = result.encode()

    return result