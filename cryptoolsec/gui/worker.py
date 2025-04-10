# cryptoolsec/gui/worker.py
# -*- coding: utf-8 -*-
"""
Worker object for running cryptographic operations in a background thread,
communicating results and progress via Qt signals.
"""

import logging
from PySide6.QtCore import QObject, Signal

# Import core logic functions and custom exceptions
# Ensure these paths are correct relative to the project structure
try:
    from ..core.file_handler import process_encryption_io, process_decryption_io
    from ..utils.exceptions import AuthenticationError, FileAccessError, ArgumentError, CryptoCLIError
except ImportError as e:
    logging.critical(f"Worker: Failed to import core modules: {e}", exc_info=True)
    # In a real app, might want to raise this to prevent GUI from starting improperly
    raise

class CryptoWorker(QObject):
    """
    QObject worker that performs encryption or decryption in a separate thread.

    Signals:
        finished(bool, str): Emitted when the operation completes.
                             Args: success (bool), message (str).
        progress(int): Emitted periodically during the operation.
                       Args: percentage (int, 0-100), or -1 for indeterminate.
    """
    finished = Signal(bool, str)
    progress = Signal(int)

    def __init__(self, mode: str, input_path: str | None, output_path: str | None, secret_bytes: bytes, is_key: bool, parent: QObject | None = None):
        """
        Initialize the worker with operation parameters.

        Args:
            mode: 'encrypt' or 'decrypt'.
            input_path: Path to input file or None for stdin.
            output_path: Path to output file or None for stdout.
            secret_bytes: The key or password bytes.
            is_key: True if secret_bytes is a key, False if it's a password.
            parent: Parent QObject.
        """
        super().__init__(parent)
        # Store parameters for the run method
        self.mode = mode
        self.input_path = input_path
        self.output_path = output_path
        self.secret_bytes = secret_bytes
        self.is_key = is_key
        # Flag to allow for potential future cancellation
        self._is_running = True
        logging.debug(f"CryptoWorker initialized for mode '{self.mode}'")

    # This method MUST NOT be decorated with @Slot if it's meant to run via thread.started.connect
    def run(self):
        """
        Execute the cryptographic operation (encryption or decryption).
        This method is intended to be run in a separate thread.
        It calls the appropriate function from core.file_handler and
        emits the 'finished' signal upon completion or error.
        It also passes a callback to the core function to emit 'progress' signals.
        """
        if not self._is_running:
            self.finished.emit(False, "Operation cancelled before start.")
            return

        logging.info(f"Worker starting {self.mode} operation in background thread...")
        success = False
        # Default error message if an unexpected exception occurs before specific handling
        message = f"{self.mode.capitalize()} failed unexpectedly."

        try:
            # Define the progress callback function linked to the signal
            def report_progress(value: int):
                # Check running flag in case operation is cancelled mid-callback
                if self._is_running:
                    self.progress.emit(value)

            # Call the appropriate core function based on mode
            if self.mode == 'encrypt':
                 process_encryption_io(
                     self.input_path, self.output_path, self.secret_bytes, self.is_key,
                     progress_callback=report_progress
                 )
                 # If process_*_io completes without raising exception, it was successful
                 success = True
                 message = f"{self.mode.capitalize()} completed successfully."

            elif self.mode == 'decrypt':
                 process_decryption_io(
                     self.input_path, self.output_path, self.secret_bytes, self.is_key,
                     progress_callback=report_progress
                 )
                 success = True
                 message = f"{self.mode.capitalize()} completed successfully."
            else:
                 # This case indicates a programming error if reached
                 raise ValueError(f"Invalid mode specified for worker: {self.mode}")

        # --- Handle specific expected exceptions from core functions ---
        except AuthenticationError as e:
            success = False
            # Use the specific message from the exception
            message = f"{self.mode.capitalize()} failed: {e}"
            # Logging already done in file_handler or crypto_logic
        except FileAccessError as e:
            success = False
            message = f"{self.mode.capitalize()} failed: {e}"
            # Logging already done
        except ArgumentError as e:
            success = False
            message = f"{self.mode.capitalize()} failed: {e}"
            # Logging already done
        except CryptoCLIError as e: # Catch our base app error
            success = False
            message = f"{self.mode.capitalize()} failed: {e}"
            # Logging already done
        except Exception as e: # Catch any other unexpected exceptions
            success = False
            message = f"An unexpected error occurred during {self.mode}: {e}"
            # Log unexpected exceptions critically here
            logging.critical(f"Unexpected error in worker run: {e}", exc_info=True)
        finally:
            # Ensure the finished signal is emitted exactly once
            if self._is_running:
                logging.info(f"Worker finished. Success: {success}. Message: {message}")
                self.finished.emit(success, message)
            # Mark as no longer running (though cancellation isn't fully implemented)
            self._is_running = False

    # Optional: Method to signal cancellation (would need checking within run/file_handler)
    # @Slot()
    # def stop_operation(self):
    #     logging.info("Stop requested for worker operation.")
    #     self._is_running = False