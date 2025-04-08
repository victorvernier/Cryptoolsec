# exceptions.py
# -*- coding: utf-8 -*-
"""Custom exception classes for the Cryptoolsec application."""

class CryptoCLIError(Exception):
    """Base class for application-specific errors."""
    pass

class FileAccessError(CryptoCLIError):
    """Error related to file access (not found, permissions, I/O)."""
    pass

class AuthenticationError(CryptoCLIError):
    """Error related to authentication/verification (bad password/key, MAC check fail)."""
    pass

class ArgumentError(CryptoCLIError):
    """Error related to invalid arguments or configuration."""
    pass