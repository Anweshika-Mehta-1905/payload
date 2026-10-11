"""
Encoding utilities for benign mock strings.

Supports Base64, ROT13, and a simple repeating-key XOR cipher.
Intended strictly for education: demonstrates reversible text transforms.
"""

import base64
import codecs


def base64_encode(plaintext: str) -> str:
    """Encode a UTF-8 string as Base64 text."""
    return base64.b64encode(plaintext.encode("utf-8")).decode("ascii")


def base64_decode(encoded: str) -> str:
    """Decode a Base64 string back into UTF-8 text."""
    return base64.b64decode(encoded.encode("ascii")).decode("utf-8")


def rot13_transform(text: str) -> str:
    """Apply ROT13. ROT13 is its own inverse, so the same call also decodes."""
    return codecs.encode(text, "rot_13")


def xor_encode(plaintext: str, key: str) -> str:
    """
    XOR each byte of the plaintext with a repeating user-defined key.
    Returns the result as a hex string so it stays printable.
    """
    _validate_key(key)
    data = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return result.hex()


def xor_decode(hex_text: str, key: str) -> str:
    """Reverse xor_encode using the same key."""
    _validate_key(key)
    data = bytes.fromhex(hex_text)
    key_bytes = key.encode("utf-8")
    decoded = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return decoded.decode("utf-8")


def _validate_key(key: str) -> None:
    if not key:
        raise ValueError("XOR key must not be empty.")
