# crypto_logic.py
# -*- coding: utf-8 -*-
"""Core cryptographic primitives: key derivation, salt generation."""

import os
import logging
import argon2
from argon2.exceptions import HashingError # Import specific exception

# Import constants and custom exceptions
# Assuming this file is in core/, utils/ is a sibling package dir
from ..utils.constants import (
    AES_KEY_BYTES,
    SALT_BYTES,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM
)
from ..utils.exceptions import CryptoCLIError, ArgumentError # ArgumentError might also be relevant

logger = logging.getLogger(__name__)

def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_BYTES)

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a key from the password and salt using Argon2id.

    Args:
        password: The password bytes.
        salt: The salt bytes (must match SALT_BYTES length).

    Returns:
        The derived key bytes (intended to be AES_KEY_BYTES length).

    Raises:
        ArgumentError: If the provided salt has an invalid length.
        CryptoCLIError: If Argon2 key derivation fails for other reasons.
    """
    logger.info("Deriving key using Argon2id...")
    if len(salt) != SALT_BYTES:
        msg = f"Invalid salt length provided for key derivation. Expected {SALT_BYTES}, got {len(salt)}."
        logger.error(msg)
        # Using ArgumentError here as it relates to invalid input parameter format/value
        raise ArgumentError(msg)

    try:
        # Use argon2 low-level API for direct control over parameters
        key = argon2.low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=AES_KEY_BYTES, # Request AES_KEY_BYTES length
            type=argon2.Type.ID # Use Argon2id variant
        )
        # Log the *actual* length of the key returned for better diagnostics
        logger.info(f"Key derived successfully ({len(key)} bytes).") # <-- Alterado aqui
        return key
    except HashingError as e:
        # Catch specific Argon2 hashing errors
        msg = f"Argon2 key derivation failed: {e}"
        logger.error(msg, exc_info=True)
        # Wrap Argon2 specific error into our application's error hierarchy
        raise CryptoCLIError(msg) from e
    except Exception as e:
        # Catch any other unexpected errors during the hashing process
        msg = f"Unexpected error during key derivation: {e}"
        logger.error(msg, exc_info=True)
        raise CryptoCLIError(msg) from e