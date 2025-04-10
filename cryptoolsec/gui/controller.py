# cryptoolsec/gui/controller.py
# -*- coding: utf-8 -*-
"""Controller class for the Cryptoolsec GUI application logic."""

import logging
import sys
from PySide6.QtCore import QObject, QThread, Slot

# Import View, Widgets, Worker, and Exceptions using relative paths
try:
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from .main_window import MainWindow # Use quoted string or TYPE_CHECKING

    from .file_selectors_widget import FileSelectorsWidget
    from .secret_input_widget import SecretInputWidget
    from .worker import CryptoWorker
    # Note '..' for utils, assuming controller.py is in gui/ which is sibling to utils/
    from ..utils.exceptions import AuthenticationError, FileAccessError, ArgumentError, CryptoCLIError
except ImportError as e:
    logging.critical(f"Controller: Failed to import necessary GUI/Util modules: {e}", exc_info=True)
    raise

logger = logging.getLogger(__name__) # Module-specific logger

class AppController(QObject):
    """
    Manages the application's GUI logic, interactions between the View (MainWindow)
    and the Core logic (via CryptoWorker in a background thread).
    """

    def __init__(self, main_window: 'MainWindow', file_selectors: FileSelectorsWidget, secret_input: SecretInputWidget, parent: QObject | None = None):
        """
        Initialize the controller. Args documented in previous versions.
        """
        super().__init__(parent)
        self.main_window = main_window
        self.file_selectors = file_selectors
        self.secret_input = secret_input
        self.worker_thread: QThread | None = None
        self.worker: CryptoWorker | None = None
        logger.debug("AppController initialized.")

    def _start_operation(self, mode: str):
        """
        Validates inputs and launches the crypto operation in a background thread.
        (Includes extra debug logging from previous steps)
        """
        if self.worker_thread and self.worker_thread.isRunning():
             logger.warning("Operation already in progress. New request ignored.")
             self.main_window.show_message("Busy", "Another operation is already running.", "warning")
             return
        logger.info(f"Controller: Start {mode} requested.")

        logger.debug("Getting input path...")
        input_path = self.file_selectors.get_input_path()
        logger.debug(f"Input path: {input_path}")
        logger.debug("Getting output path...")
        output_path = self.file_selectors.get_output_path()
        logger.debug(f"Output path: {output_path}")

        if not input_path or not output_path:
             logger.warning("Validation failed: Input or output path missing.")
             self.main_window.show_message("Missing Files", "Please select both input and output files.", "warning")
             return
        logger.debug("File paths seem ok.")

        logger.debug("Getting validated secret...")
        secret_bytes, is_key = self.secret_input.get_validated_secret()
        if secret_bytes is None:
             logger.warning("Validation failed: Secret validation returned None.")
             return
        logger.debug(f"Secret obtained. Is key: {is_key}")

        logger.info(f"Inputs validated for {mode}. Starting background task...")
        logger.debug("Setting UI to busy state...")
        self.main_window.set_ui_busy(True)
        logger.debug("UI set to busy.")

        try:
            logger.debug("Creating QThread...")
            self.worker_thread = QThread(self)
            logger.debug("QThread created. Creating CryptoWorker...")
            self.worker = CryptoWorker(mode, input_path, output_path, secret_bytes, is_key)
            logger.debug("CryptoWorker created.")

            logger.debug("Moving worker to thread...")
            self.worker.moveToThread(self.worker_thread)
            logger.debug("Worker moved.")

            logger.debug("Connecting signals...")
            self.worker_thread.started.connect(self.worker.run)
            self.worker.progress.connect(self._update_progress)
            self.worker.finished.connect(self._operation_finished)
            self.worker.finished.connect(self.worker_thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.worker_thread.finished.connect(self.worker_thread.deleteLater)
            logging.debug("Signals connected.")

            logger.debug("Starting thread...")
            self.worker_thread.start()
            logging.debug("Background thread started.")

        except Exception as e:
             logger.critical(f"Failed to setup or start worker thread: {e}", exc_info=True)
             self.main_window.show_message("Error", f"Failed to start operation: {e}", "critical")
             self.main_window.set_ui_busy(False)
             self.worker = None
             self.worker_thread = None

    @Slot()
    def start_encryption(self):
        """Public slot to initiate the encryption operation."""
        self._start_operation('encrypt')

    @Slot()
    def start_decryption(self):
        """Public slot to initiate the decryption operation."""
        self._start_operation('decrypt')

    # --- Slots to receive signals from the CryptoWorker ---
    @Slot(int)
    def _update_progress(self, value: int):
        """Slot to receive progress updates (percentage or -1) from the worker."""
        logger.debug(f"Controller received progress signal: {value}")
        self.main_window.update_progress(value)

    @Slot(bool, str)
    def _operation_finished(self, success: bool, message: str):
        """
        Slot called when the worker's 'finished' signal is emitted.
        Updates the UI to reflect completion status, clears inputs, and cleans up resources.

        Args:
            success: True if the operation completed successfully, False otherwise.
            message: A status message describing the outcome.
        """
        logger.debug(f"Controller executing _operation_finished. Success: {success}")
        logger.info(f"Controller received finished signal. Success: {success}, Message: '{message}'")

        # Update progress bar to final state
        logger.debug("Updating progress bar to final state.")
        self.main_window.update_progress(100 if success else 0)

        # Re-enable UI elements
        logger.debug("Setting UI to not busy.")
        self.main_window.set_ui_busy(False)

        # Display final result message
        logger.debug("Showing final message.")
        msg_level = "info" if success else "error"
        title = "Success" if success else "Operation Failed"
        self.main_window.show_message(title, message, msg_level)

        # --- Clear Input Fields (NEW) ---
        # Clear file paths and secret inputs for the next operation
        logger.debug("Clearing UI fields after operation.")
        self.file_selectors.clear_all()
        # Ensure SecretInputWidget has a clear_secrets method
        if hasattr(self.secret_input, 'clear_secrets') and callable(self.secret_input.clear_secrets):
             self.secret_input.clear_secrets()
        else:
             logger.warning("SecretInputWidget does not have a 'clear_secrets' method.")
        # --------------------------------

        # Clean up references
        logger.debug("Clearing worker/thread references in controller.")
        self.worker = None
        self.worker_thread = None
        logger.debug("Worker thread and worker object references cleared.")