"""
String-level obfuscation utilities for benign mock strings.

- String splitting: breaks a string into concatenated chunks.
- Noise insertion: sprinkles reserved noise characters into a string.
  A matching decoder can strip them back out, which is the point of the demo.
"""

import random
from typing import List, Optional

# Reserved noise alphabet. Payloads containing these characters are rejected
# so that noise removal is always exact.
NOISE_CHARS = "#%&*@~^"


def split_string(
    text: str,
    min_chunk: int = 1,
    max_chunk: int = 3,
    seed: Optional[int] = None,
) -> List[str]:
    """
    Randomly split a string into chunks whose sizes fall in [min_chunk, max_chunk].
    Example: "hello" -> ["he", "ll", "o"]
    """
    if min_chunk < 1 or max_chunk < min_chunk:
        raise ValueError("Invalid chunk size range: need 1 <= min_chunk <= max_chunk.")

    rng = random.Random(seed)
    chunks: List[str] = []
    index = 0
    while index < len(text):
        size = rng.randint(min_chunk, max_chunk)
        chunks.append(text[index:index + size])
        index += size
    return chunks


def join_chunks(chunks: List[str]) -> str:
    """Reassemble split chunks into the original string."""
    return "".join(chunks)


def chunks_to_expression(chunks: List[str]) -> str:
    """
    Render chunks as a concatenation expression, e.g. 'he' + 'll' + 'o'.
    Useful for showing how the split would look in a source-level snippet.
    """
    return " + ".join(repr(chunk) for chunk in chunks)


def insert_noise(text: str, noise_rate: float = 0.3, seed: Optional[int] = None) -> str:
    """
    After each character, insert a random noise character with probability noise_rate.
    Raises ValueError if the text already contains reserved noise characters.
    """
    if not 0.0 <= noise_rate <= 1.0:
        raise ValueError("noise_rate must be between 0.0 and 1.0.")

    overlap = set(text) & set(NOISE_CHARS)
    if overlap:
        raise ValueError(
            "Payload contains reserved noise characters: "
            + "".join(sorted(overlap))
        )

    rng = random.Random(seed)
    output: List[str] = []
    for char in text:
        output.append(char)
        if rng.random() < noise_rate:
            output.append(rng.choice(NOISE_CHARS))
    return "".join(output)


def remove_noise(text: str) -> str:
    """Strip reserved noise characters, reversing insert_noise()."""
    return "".join(ch for ch in text if ch not in NOISE_CHARS)
