"""
package/data.py

This file contains the specifications of the algorithms used.
This makes it easy to add new algorithms.
"""

VERSION_MULTICODE = "2.1"

# Aliases commands
ALIASES_CMD = {"h": "hash", "k": "key", "e": "encrypt", "d": "decrypt"}

#List of available algorithms for the --list option.
LIST_ALGO = {
"cipher": {"Encodings": ["hex/base16", "base32", "base64", "base58", "base85", "base92"],
           "Legacy ciphers": ["caesar", "des", "3des", "blowfish", "rc2", "cast-128", "rsa-pkcs1.5"],
           "Modern algorithms": ["aes", "fernet", "salsa20", "chacha20", "chacha-20poly1305",
                                 "rsa-oaep", "serpent", "camellia", "sm4"]},

"hash": {"Hash functions": ["ripemd160", "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384",
                                      "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"],
                   "Extensible-Output Functions": ["keccak", "shake128", "shake256", "cshake128", "cshake256",
                                                   "kangarootwelve", "blake2b", "blake2s"],
                   "MACs": ["hmac", "aes-cmac", "poly1305-aes", "poly1305-chacha20", "kmac128", "kmac256"],
                   "Key Derivation Functions": ["pbkdf2", "argon2id", "bcrypt"]},

"otp": {"Time-based One Time Password": ["TOTP"], "Counter-based One Time Password": ["HOTP"]},

"signature": {"digital signature algorithms": ["rsassa", "pss", "dss", "eddsa"]},

"key": {"public key algorithms": ["rsa", "dsa", "ecc"]},

"padding": {"padding algorithms": ["pkcs7", "ansix923"]}
}

# Modules to import according to the signature algorithm.
SIGN_ALGO_MODULES = {"rsassa": ["Cryptodome.Signature.pkcs1_15", "PublicKey.RSA"],
                     "pss": ["Cryptodome.Signature.pss", "PublicKey.RSA"],
                     "dss": ["Cryptodome.Signature.DSS", "PublicKey.ECC"],
                     "eddsa": ["Cryptodome.Signature.eddsa", "PublicKey.ECC"]}

# Specific options (available only for some algorithms) and their parameters.
SPECIFIC_OPTIONS = {"key": {"metavar": "KEY", "description": ""},
                    "digest_bits": {"metavar": "LENGTH_BITS", "description": "Output length in bits"},
                    "hash_len": {"metavar": "ARGON2_LENGTH_BITS", "description": " Length of the argon2 hash in bytes"},
                    "number_keys": {"metavar": "NB_KEYS", "description": "Number of keys to generate"},
                    "custom": {"metavar": "CUSTOM_STR", "description": "A customization string"},
                    "nonce": {"metavar": "NONCE", "description": "Unique and random nonce"},
                    "salt": {"metavar": "SALT", "description": "hexadecimal, base32 or base64 salt"},
                    "salt_len": {"metavar": "ARGON2_LENGTH_SALT_BITS", "description": " Length of random salt to generate"},
                    "count": {"metavar": "NB_ITERATIONS",
                              "description": "Number of hash iterations for pbkdf2"},
                    "hash": {"metavar": "HASH_FUNCTION", "description": "Hash function (first category of --list)"},
                    "cost": {"metavar": "COST", "description": "The exponential factor of iterations"
                                                               "\nThe higher it is, the slower the hashing"},
                    "iv": {"metavar": "IV", "description": "Random initialization vector"},
                    "mac_len": {"metavar": "MAC_LEN", "description": "The desired length of the MAC tag"},
                    "segment_size": {"metavar": "SEGMENT_SIZE",
                                     "description": "The number of bits the plaintext and ciphertext are segmented in"},
                    "initial_value": {"metavar": "INIT_VALUE",
                                      "description": "The value of the counter for the first counter block"},
                    "iterations": {"metavar": "ARGON2_ITERATIONS",
                                  "description": " Defines the amount of computation realized and therefore the execution time"},
                    "memory_cost": {"metavar": "ARGON2_MEMORY_COST",
                                               "description": " Defines the memory usage, given in kibibytes"},
                    "parallelism": {"metavar": "ARGON2_PARALLELISM_COST",
                                    "description": " Defines the number of parallel threads"}
                    }

# Specifications of block cipher operation modes.
MODE_SPECS = {"ecb": {"padding": True, "mac": False},
              "cbc": {"padding": True, "mac": False},
              "cfb": {"padding": False, "mac": False},
              "ofb": {"padding": False, "mac": False},
              "ctr": {"padding": False, "mac": False},
              "ccm": {"padding": False, "mac": True},
              "eax": {"padding": False, "mac": True},
              "gcm": {"padding": False, "mac": True},
              "siv": {"padding": False, "mac": True},
              "ocb": {"padding": False, "mac": True},
              }

# OTP algorithms specifications.
SPECS_OTPS = {
    "HOTP": {
        "args": {
            "key": {
                "default": 160,
                "prompt": " (KEY/8/../[160]/..)",
                "type": bytes
            },
            "length": {
                "default": 6,
                "prompt": " ([6]/7/8)",
                "type": int
            },
            "counter": {
                "default": 0,
                "prompt": " ([0]/..)",
                "type": int
            },
            "hash": {
                "option": False,
                "prompt": " (hash function ([sha1]/sha256/sha512))",
                "default": "sha1",
                "type": "module"
            }
        }
    },
    "TOTP": {
        "args": {
            "key": {
                "default": 160,
                "prompt": " (KEY/8/../[160]/..)",
                "type": bytes
            },
            "length": {
                "default": 6,
                "prompt": " ([6]/7/8)",
                "type": int
            },
            "time_step": {
                "default": 30,
                "prompt": " (../[30]/..)",
                "type": int
            },
            "hash": {
                "option": False,
                "prompt": " (hash function ([sha1]/sha256/sha512))",
                "default": "sha1",
                "type": "module"
            }
        }
    }
}


# Encryption algorithms specifications.
SPECS_CIPHERS = {"base16": {"module": "base64"}, "base32": {"module": "base64"},
                "base64": {"module": "base64"}, "base85": {"module": "base64"},
                "base58": {"module": "base58"}, "base92": {"module": "base92"},
                "caesar": {"args": {"key": {"option": False,
                                            "default": 7,
                                            "prompt": " (Shift Key Number)",
                                            "type": int}},
                          "module": "package.caesar"},
                "salsa20": {"args": {"key": {"option": False,
                                             "default": 32,
                                             "prompt": " (KEY/128/[256])",
                                             "type": bytes},
                                     "nonce": {"option": False,
                                               "default": 8,
                                               "prompt": " (NONCE/[64])",
                                               "type": bytes}},
                            "module": "Cryptodome.Cipher.Salsa20"},
                 "chacha20": {"args": {"key": {"option": False,
                                              "default": 32,
                                              "prompt": " (KEY/[256])",
                                              "type": bytes},
                                      "nonce": {"option": False,
                                                "default": 12,
                                                "prompt": " (NONCE/64/[96]/ 192 for XChaCha20)",
                                                "type": bytes}},
                             "module": "Cryptodome.Cipher.ChaCha20"},
                 "chacha20-poly1305": {"args": {"key": {"option": False,
                                                       "default": 32,
                                                       "prompt": " (KEY/[256])",
                                                       "type": bytes},
                                               "nonce": {"option": False,
                                                         "default": 12,
                                                         "prompt": " (NONCE/64/[96]/ 192 for XChaCha20)",
                                                         "type": bytes}},
                                      "module": "Cryptodome.Cipher.ChaCha20_Poly1305"},
                 "aes": {"args": {"key": {"option": False,
                                         "default": 16,
                                         "prompt": " (KEY/[128]/192/256)",
                                         "type": bytes}},
                        "modes": {"ecb": {},
                                  "cbc": {"iv": {"option": False,
                                                 "default": 16,
                                                 "prompt": " (IV/[128])",
                                                 "type": bytes}},
                                  "cfb": {"iv": {"option": False,
                                                 "default": 16,
                                                 "prompt": " (IV/[128])",
                                                 "type": bytes},
                                          "segment_size": {"option": False,
                                                           "default": 8,
                                                           "prompt": " ([8]/16/..)",
                                                           "type": int}},
                                  "ofb": {"iv": {"option": False,
                                                 "default": 16,
                                                 "prompt": " (IV/[128])",
                                                 "type": bytes}},
                                  "ctr": {"nonce": {"option": False,
                                                    "default": 8,
                                                    "prompt": " (NONCE/0/../[64]/../120)",
                                                    "type": bytes},
                                          "initial_value": {"option": False,
                                                            "default": 0,
                                                            "prompt": " ([0]/..)",
                                                            "type": int}},
                                  "ccm": {"nonce": {"option": False,
                                                    "default": 11,
                                                    "prompt": " (NONCE/56/../[88]/../104)",
                                                    "type": bytes},
                                          "mac_len": {"option": False,
                                                      "default": 128,
                                                      "prompt": " (32/../[128])",
                                                      "type": int}},
                                  "eax": {"nonce": {"option": False,
                                                    "default": 16,
                                                    "prompt": " (NONCE/../[128]/..)",
                                                    "type": bytes},
                                          "mac_len": {"option": False,
                                                      "default": 128,
                                                      "prompt": " (32/../[128])",
                                                      "type": int}},
                                  "gcm": {"nonce": {"option": False,
                                                    "default": 16,
                                                    "prompt": " (NONCE/../[128]/..)",
                                                    "type": bytes},
                                          "mac_len": {"option": False,
                                                      "default": 128,
                                                      "prompt": " (32/../[128])",
                                                      "type": int}},
                                  "siv": {"key": {"option": False,
                                                  "default": 32,
                                                  "prompt": " (KEY/[256]/384/512)",
                                                  "type": bytes},
                                      "nonce": {"option": True,
                                                "prompt": " (optional: NONCE/../128/..)",
                                                "type": bytes}},
                                  "ocb": {"nonce": {"option": False,
                                                    "default": 15,
                                                    "prompt": " (NONCE/8/../[120])",
                                                    "type": bytes},
                                          "mac_len": {"option": False,
                                                      "default": 128,
                                                      "prompt": " (32/../[128])",
                                                      "type": int}},
                                  },
                        "module": "Cryptodome.Cipher.AES"},
                 "fernet": {"args": {"key": {"option": False,
                                            "default": 32,
                                            "prompt": " (KEY/[256])",
                                            "type": bytes}},
                           "module": "cryptography.fernet"},
                 "serpent": {"args": {"key": {"option": False,
                                             "default": 16,
                                             "prompt": " (KEY/[128]/192/256)",
                                             "type": bytes}},
                            "modes": {"ecb": {},
                                      "cbc": {"iv": {"option": False,
                                                     "default": 16,
                                                     "prompt": " (IV/[128])",
                                                     "type": bytes}}},
                            "module": "pyserpent"},
                 "rc2": {"args": {"key": {"option": False,
                                          "default": 16,
                                          "prompt": " (KEY/5/../[128])",
                                          "type": bytes}},
                                 "modes": {"ecb": {},
                                           "cbc": {"iv": {"option": False,
                                                   "default": 8,
                                                   "prompt": " (IV/[64])",
                                                   "type": bytes}},
                                           "cfb": {"iv": {"option": False,
                                                          "default": 8,
                                                          "prompt": " (IV/[64])",
                                                          "type": bytes},
                                                   "segment_size": {"option": False,
                                                                    "default": 8,
                                                                    "prompt": " ([8]/16/..)",
                                                                    "type": int}},
                                           "ofb": {"iv": {"option": False,
                                                          "default": 8,
                                                          "prompt": " (IV/[64])",
                                                          "type": bytes}},
                                           "ctr": {"nonce": {"option": False,
                                                             "default": 7,
                                                             "prompt": " (NONCE/0/../[56])",
                                                             "type": bytes},
                                                   "initial_value": {"option": False,
                                                                     "default": 0,
                                                                     "prompt": " ([0]/..)",
                                                                     "type": int}},
                                           "eax": {"nonce": {"option": False,
                                                             "default": 16,
                                                             "prompt": " (NONCE/../[128]/..)",
                                                             "type": bytes},
                                                   "mac_len": {"option": False,
                                                               "default": 8,
                                                               "prompt": " (../[64])",
                                                               "type": int}}},
                            "module": "Cryptodome.Cipher.ARC2"},
                 "rc4": {"args": {"key": {"option": False,
                                          "default": 32,
                                          "prompt": " (KEY/8/../[256]/../2048)",
                                          "type": bytes}},
                             "module": "Cryptodome.Cipher.ARC4"},
                 "cast-128": {"args": {"key": {"option": False,
                                          "default": 16,
                                          "prompt": " (KEY/40/../[128])",
                                          "type": bytes}},
                             "modes": {"ecb": {},
                                       "cbc": {"iv": {"option": False,
                                               "default": 8,
                                               "prompt": " (IV/[64])",
                                               "type": bytes}},
                                       "cfb": {"iv": {"option": False,
                                                      "default": 8,
                                                      "prompt": " (IV/[64])",
                                                      "type": bytes},
                                               "segment_size": {"option": False,
                                                                "default": 8,
                                                                "prompt": " ([8]/16/..)",
                                                                "type": int}},
                                       "ofb": {"iv": {"option": False,
                                                      "default": 8,
                                                      "prompt": " (IV/[64])",
                                                      "type": bytes}},
                                       "ctr": {"nonce": {"option": False,
                                                         "default": 7,
                                                         "prompt": " (NONCE/0/../[56])",
                                                         "type": bytes},
                                               "initial_value": {"option": False,
                                                                 "default": 8,
                                                                 "prompt": " ([8]/..)",
                                                                 "type": int}},
                                       "eax": {"nonce": {"option": False,
                                                         "default": 16,
                                                         "prompt": " (NONCE/../[128]/..)",
                                                         "type": bytes},
                                               "mac_len": {"option": False,
                                                           "default": 8,
                                                           "prompt": " (../[64])",
                                                           "type": int}}},
                        "module": "Cryptodome.Cipher.CAST"},
                 "blowfish": {"args": {"key": {"option": False,
                                              "default": 16,
                                              "prompt": " (KEY/32/../[128]/../448)",
                                              "type": bytes}},
                             "modes": {"ecb": {},
                                       "cbc": {"iv": {"option": False,
                                               "default": 8,
                                               "prompt": " (IV/[64])",
                                               "type": bytes}},
                                       "cfb": {"iv": {"option": False,
                                                      "default": 8,
                                                      "prompt": " (IV/[64])",
                                                      "type": bytes},
                                               "segment_size": {"option": False,
                                                                "default": 8,
                                                                "prompt": " ([8]/16/..)",
                                                                "type": int}},
                                       "ofb": {"iv": {"option": False,
                                                      "default": 8,
                                                      "prompt": " (IV/[64])",
                                                      "type": bytes}},
                                       "ctr": {"nonce": {"option": False,
                                                         "default": 7,
                                                         "prompt": " (NONCE/0/../[56])",
                                                         "type": bytes},
                                               "initial_value": {"option": False,
                                                                 "default": 0,
                                                                 "prompt": " ([0]/..)",
                                                                 "type": int}},
                                       "eax": {"nonce": {"option": False,
                                                         "default": 16,
                                                         "prompt": " (NONCE/../[128]/..)",
                                                         "type": bytes},
                                               "mac_len": {"option": False,
                                                           "default": 64,
                                                           "prompt": " (../[64])",
                                                           "type": int}}},
                        "module": "Cryptodome.Cipher.Blowfish"},
                 "3des": {"args": {"key": {"option": False,
                                          "default": 24,
                                          "prompt": " (KEY/128/[192])",
                                          "type": bytes}},
                         "modes": {"ecb": {},
                                   "cbc": {"iv": {"option": False,
                                           "default": 8,
                                           "prompt": " (IV/[64])",
                                           "type": bytes}},
                                   "cfb": {"iv": {"option": False,
                                                  "default": 8,
                                                  "prompt": " (IV/[64])",
                                                  "type": bytes},
                                           "segment_size": {"option": False,
                                                            "default": 8,
                                                            "prompt": " ([8]/16/..)",
                                                            "type": int}},
                                   "ofb": {"iv": {"option": False,
                                                  "default": 8,
                                                  "prompt": " (IV/[64])",
                                                  "type": bytes}},
                                   "ctr": {"nonce": {"option": False,
                                                     "default": 7,
                                                     "prompt": " (NONCE/0/../[56])",
                                                     "type": bytes},
                                           "initial_value": {"option": False,
                                                             "default": 0,
                                                             "prompt": " ([0]/..)",
                                                             "type": int}},
                                   "eax": {"nonce": {"option": False,
                                                     "default": 16,
                                                     "prompt": " (NONCE/../[128]/..)",
                                                     "type": bytes},
                                           "mac_len": {"option": False,
                                                       "default": 64,
                                                       "prompt": " (../[64])",
                                                       "type": int}}},
                         "module": "Cryptodome.Cipher.DES3"},
                 "des": {"args": {"key": {"option": False,
                                         "default": 8,
                                         "prompt": " (KEY/[64])",
                                         "type": bytes}},
                        "modes": {"ecb": {},
                                  "cbc": {"iv": {"option": False,
                                           "default": 8,
                                           "prompt": " (IV/[64])",
                                           "type": bytes}},
                                  "cfb": {"iv": {"option": False,
                                                  "default": 8,
                                                  "prompt": " (IV/[64])",
                                                  "type": bytes},
                                           "segment_size": {"option": False,
                                                            "default": 8,
                                                            "prompt": " ([8]/16/..)",
                                                            "type": int}},
                                  "ofb": {"iv": {"option": False,
                                                 "default": 8,
                                                 "prompt": " (IV/[64])",
                                                 "type": bytes}},
                                  "ctr": {"nonce": {"option": False,
                                                    "default": 7,
                                                    "prompt": " (NONCE/0/../[56])",
                                                    "type": bytes},
                                           "initial_value": {"option": False,
                                                             "default": 0,
                                                             "prompt": " ([0]/..)",
                                                             "type": int}},
                                  "eax": {"nonce": {"option": False,
                                                    "default": 16,
                                                    "prompt": " (NONCE/../[128]/..)",
                                                    "type": bytes},
                                          "mac_len": {"option": False,
                                                      "default": 64,
                                                      "prompt": " (../[64])",
                                                      "type": int}}},
                        "module": "Cryptodome.Cipher.DES"},
                 "rsa-pkcs1.5": {"module": "Cryptodome.Cipher.PKCS1_v1_5"},
                 "rsa-aoep": {"module": "Cryptodome.Cipher.PKCS1_OAEP"},
                 }

# Hash algorithms specifications.
SPECS_HASHS = {
    "ripemd160": {},
    "md2": {},
    "md5": {},
    "sha1": {},
    "sha224": {},
    "sha256": {},
    "sha384": {},
    "sha512": {
        "args": {
            "digest_bits": {
                "option": True,
                "prompt": " (optional: 224/256)",
                "type": int
            }
        }
    },
    "sha3-224": {},
    "sha3-256": {},
    "sha3-384": {},
    "sha3-512": {},
    "keccak": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (224/[256]/384/512)",
                "default": 512,
                "type": int
            }
        }
    },
    "shake128": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[128]/..)",
                "default": 128,
                "type": int
            }
        },
        "type": "XOF"
    },
    "shake256": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[256]/..)",
                "default": 256,
                "type": int
            }
        },
        "type": "XOF"
    },
    "cshake128": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[128]/..)",
                "default": 128,
                "type": int
            },
            "custom": {
                "option": False,
                "prompt": " (optional)",
                "type": str
            }
        },
        "type": "XOF"
    },
    "cshake256": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[256]/..)",
                "default": 256,
                "type": int
            },
            "custom": {
                "option": False,
                "prompt": " (optional)",
                "type": str,
                "default": None
            }
        },
        "type": "XOF"
    },
    "kangarootwelve": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[256]/..)",
                "default": 256,
                "type": int
            },
            "custom": {
                "option": False,
                "prompt": " (optional)",
                "type": str,
                "default": None
            }
        },
        "type": "XOF"
    },
    "blake2b": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[512])",
                "default": 512,
                "type": int
            },
            "key": {
                "option": True,
                "prompt": " (optional)",
                "type": str
            }
        }
    },
    "blake2s": {
        "args": {
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/24/../[256])",
                "default": 256,
                "type": int
            },
            "key": {
                "option": True,
                "prompt": " (optional)",
                "type": str
            }
        }
    },
    "hmac": {
        "args": {
            "key": {
                "option": False,
                "prompt": "",
                "default": "",
                "type": str
            },
            "hash": {
                "option": False,
                "prompt": " (hash function [sha256])",
                "default": "sha256",
                "type": "module"
            }
        }
    },
    "aes-cmac": {
        "args": {
            "key": {
                "option": False,
                "prompt": " (KEY/[128])",
                "default": 16,
                "type": bytes
            }
        }
    },
    "poly1305-aes": {
        "args": {
            "key": {
                "option": False,
                "prompt": " (KEY/[256])",
                "default": 32,
                "type": bytes
            },
            "nonce": {
                "option": False,
                "prompt": " (NONCE/[128])",
                "default": 16,
                "type": bytes
            }
        }
    },
    "poly1305-chacha20": {
        "args": {
            "key": {
                "option": False,
                "prompt": " (KEY/[256])",
                "default": 32,
                "type": bytes
            },
            "nonce": {
                "option": False,
                "prompt": " (NONCE/64/[96])",
                "default": 12,
                "type": bytes
            }
        }
    },
    "kmac128": {
        "args": {
            "key": {
                "option": False,
                "prompt": " (KEY/128/../[256]/..)",
                "default": 32,
                "type": bytes
            },
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/../[64]/..)",
                "default": 64,
                "type": int
            },
            "custom": {
                "option": False,
                "prompt": " (optional)",
                "type": str,
                "default": ""
            }
        }
    },
    "kmac256": {
        "args": {
            "key": {
                "option": False,
                "prompt": " (KEY/[256]/..)",
                "default": 32,
                "type": bytes
            },
            "digest_bits": {
                "option": False,
                "prompt": " (8/16/../[64]/..)",
                "default": 64,
                "type": int
            },
            "verify": {
                "option": True,
                "prompt": " (optional: hash MAC to check)",
                "type": bytes
            },
        }
    },
    "argon2id": {
        "args": {
            "iterations": {
                "option": False,
                "prompt": " ([3]/..)",
                "default": 3,
                "type": int
            },
            "memory_cost": {
                "option": False,
                "prompt": " (../[4096]/..)",
                "default": 4096,
                "type": int
            },
            "parallelism": {
                "option": False,
                "prompt": " (../[4]/..)",
                "default": 4,
                "type": int
            },
            "hash_len": {
                "option": False,
                "prompt": " (../[32]/..)",
                "default": 32,
                "type": int
            },
            "salt_len": {
                "option": False,
                "prompt": " (../[32]/..)",
                "default": 32,
                "type": int
            }
        }
    },
    "pbkdf2": {
        "args": {
            "salt": {
                "option": False,
                "prompt": " (SALT/[128])",
                "default": 16,
                "type": bytes
            },
            "digest_bits": {
                "option": False,
                "prompt": " (../128/../[256]/..)",
                "default": 256,
                "type": int
            },
            "count": {
                "option": False,
                "prompt": " (../[1000000]/..)",
                "default": 1000000,
                "type": int
            },
            "hash": {
                "option": False,
                "prompt": " (hash function [sha512])",
                "default": "sha512",
                "type": "module"
            }
        },
        "type": "KDF"
    },
    "bcrypt": {
        "args": {
            "salt": {
                "option": False,
                "prompt": " (SALT/[128])",
                "default": 16,
                "type": bytes
            },
            "cost": {
                "option": False,
                "prompt": " (4/../[12]/../31)",
                "default": 12,
                "type": int
            }
        },
        "type": "KDF"
    }
}

