# cryptoolsec/gui/secret_input_widget.py
# -*- coding: utf-8 -*-
"""Custom widget for selecting secret method and inputting secret."""

import logging
import os
import sys
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QGroupBox, QRadioButton, QMessageBox
)
from PySide6.QtCore import Slot

# Import helpers and exceptions
# Using fallback import pattern for local development consistency
try:
    # Assuming relative paths work from where the app is launched (e.g., via -m or installed)
    from ..cli.password_utils import read_key_file
    from ..utils.exceptions import FileAccessError, ArgumentError, CryptoCLIError
except ImportError:
     # Fallback if running script directly in a way that breaks relative imports
     if '.' not in sys.path: sys.path.append('.') # Add project root if needed
     logging.warning("SecretInputWidget: Using fallback import path.")
     # Assuming script is run from project root, hence direct package name
     from cryptoolsec.cli.password_utils import read_key_file
     from cryptoolsec.utils.exceptions import FileAccessError, ArgumentError, CryptoCLIError

logger = logging.getLogger(__name__) # Module-specific logger

class SecretInputWidget(QGroupBox):
    """Widget containing options for password or keyfile input."""

    def __init__(self, parent: QWidget | None = None):
        """Initializes the secret input widget."""
        super().__init__("Secret Method", parent)
        self._keyfile_path: str | None = None
        # References to widgets created in _init_ui
        self.radio_use_password: QRadioButton | None = None
        self.radio_use_keyfile: QRadioButton | None = None
        self.password_group_widget: QWidget | None = None
        self.keyfile_group_widget: QWidget | None = None
        self.password_edit: QLineEdit | None = None
        self.confirm_password_edit: QLineEdit | None = None
        self.keyfile_path_edit: QLineEdit | None = None
        self.keyfile_browse_button: QPushButton | None = None # Added reference for potential use

        self._init_ui()
        # Ensure initial state is correctly set based on default radio check
        self._on_secret_method_changed()

    def _init_ui(self):
        """Initialize the UI elements for this widget."""
        outer_layout = QVBoxLayout(self) # Main layout for the GroupBox

        # --- Radio Buttons ---
        radio_layout = QHBoxLayout()
        self.radio_use_password = QRadioButton("Use Password", self)
        self.radio_use_keyfile = QRadioButton("Use Key File", self)
        self.radio_use_password.setChecked(True) # Default to password
        radio_layout.addWidget(self.radio_use_password)
        radio_layout.addWidget(self.radio_use_keyfile)
        radio_layout.addStretch(1)
        outer_layout.addLayout(radio_layout)

        # --- Password Fields ---
        # Use a QWidget as a container to easily enable/disable the group
        self.password_group_widget = QWidget(self)
        password_layout = QGridLayout(self.password_group_widget)
        password_layout.setContentsMargins(0, 5, 0, 5) # Adjust margins as needed
        pwd_label = QLabel("Password:", self)
        self.password_edit = QLineEdit(self)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_pwd_label = QLabel("Confirm:", self)
        self.confirm_password_edit = QLineEdit(self)
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(pwd_label, 0, 0)
        password_layout.addWidget(self.password_edit, 0, 1)
        password_layout.addWidget(confirm_pwd_label, 1, 0)
        password_layout.addWidget(self.confirm_password_edit, 1, 1)
        outer_layout.addWidget(self.password_group_widget)

        # --- Keyfile Fields ---
        self.keyfile_group_widget = QWidget(self)
        keyfile_layout = QHBoxLayout(self.keyfile_group_widget)
        keyfile_layout.setContentsMargins(0, 5, 0, 5)
        keyfile_label = QLabel("Key File:", self)
        self.keyfile_path_edit = QLineEdit(self)
        self.keyfile_path_edit.setPlaceholderText("Select key file...")
        self.keyfile_path_edit.setReadOnly(True)
        self.keyfile_browse_button = QPushButton("Select...", self)
        keyfile_layout.addWidget(keyfile_label)
        keyfile_layout.addWidget(self.keyfile_path_edit, 1)
        keyfile_layout.addWidget(self.keyfile_browse_button)
        outer_layout.addWidget(self.keyfile_group_widget)

        # --- Connect signals ---
        self.keyfile_browse_button.clicked.connect(self._select_key_file)
        # Connect only one radio button's toggled signal is enough
        self.radio_use_password.toggled.connect(self._on_secret_method_changed)

    @Slot()
    def _select_key_file(self):
        """Opens a dialog to select the key file."""
        start_dir = os.path.dirname(self._keyfile_path) if self._keyfile_path else os.path.expanduser("~")
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Key File", start_dir, "Key Files (*.key);;All Files (*.*)"
            )
        if file_path:
            self._keyfile_path = file_path
            self.keyfile_path_edit.setText(file_path)
            logger.info(f"Key file selected: {file_path}")

    @Slot()
    def _on_secret_method_changed(self):
        """Enables/disables input fields based on the selected radio button."""
        # Check if widgets have been initialized before accessing them
        if not self.radio_use_password or not self.password_group_widget or not self.keyfile_group_widget:
             return # Avoid errors during initial setup if called too early

        use_password = self.radio_use_password.isChecked()
        logger.debug(f"Secret method toggled. Use Password: {use_password}")

        self.password_group_widget.setEnabled(use_password)
        self.keyfile_group_widget.setEnabled(not use_password)

        # Clear inactive fields
        if not use_password:
            if self.password_edit: self.password_edit.clear()
            if self.confirm_password_edit: self.confirm_password_edit.clear()
        else:
            if self.keyfile_path_edit: self.keyfile_path_edit.clear()
            self._keyfile_path = None # Clear the internal path variable too

    def get_validated_secret(self) -> tuple[bytes | None, bool]:
        """
        Gets the password or key bytes based on UI selection and validates.
        Shows message box to the parent on validation error.

        Returns:
            tuple: (secret_bytes, is_key) where is_key is True for keyfile, False for password.
                   Returns (None, False) if validation fails.
        """
        parent_window = self.parent() # Get parent for QMessageBox context

        if self.radio_use_password.isChecked():
            # Ensure widgets exist before accessing text
            if not self.password_edit or not self.confirm_password_edit:
                 logger.error("Password fields not initialized in get_validated_secret.")
                 QMessageBox.critical(parent_window, "Internal Error", "Password fields not ready.")
                 return None, False

            password = self.password_edit.text()
            confirm = self.confirm_password_edit.text()

            if not password:
                QMessageBox.warning(parent_window, "Missing Password", "Please enter the password.")
                return None, False
            if not confirm:
                 QMessageBox.warning(parent_window, "Missing Confirmation", "Please confirm the password.")
                 return None, False
            if password != confirm:
                QMessageBox.warning(parent_window, "Password Mismatch", "The entered passwords do not match.")
                return None, False

            logger.info("Password validated from GUI fields.")
            return password.encode('utf-8'), False # is_key = False

        elif self.radio_use_keyfile.isChecked():
            if not self._keyfile_path:
                QMessageBox.warning(parent_window, "Missing Key File", "Please select a key file.")
                return None, False
            try:
                # Attempt to read and validate the key file
                key_bytes = read_key_file(self._keyfile_path)
                # If read_key_file succeeds without exception, the key is valid
                logger.info("Key validated from GUI file selection.")
                return key_bytes, True # is_key = True
            except (FileAccessError, ArgumentError, CryptoCLIError) as e:
                 # read_key_file should have printed/logged details
                 QMessageBox.critical(parent_window, "Key File Error", f"Error reading key file:\n{e}")
                 return None, False
            except Exception as e: # Catch any other unexpected error during read
                 QMessageBox.critical(parent_window, "Key File Error", f"Unexpected error reading key file:\n{e}")
                 logger.error(f"Unexpected error reading key file {self._keyfile_path}", exc_info=True)
                 return None, False
        else:
             # Should not happen if radio buttons are correctly grouped
             QMessageBox.critical(parent_window, "Internal Error", "No secret method selected.")
             logger.error("Internal error: No secret radio button checked.")
             return None, False

    # --- Method to Clear Fields (Added) ---
    @Slot()
    def clear_secrets(self):
        """Clears password fields and resets keyfile path selection."""
        if self.password_edit: self.password_edit.clear()
        if self.confirm_password_edit: self.confirm_password_edit.clear()
        if self.keyfile_path_edit: self.keyfile_path_edit.clear()
        self._keyfile_path = None
        # Optional: Reset radio button to default state?
        # if self.radio_use_password: self.radio_use_password.setChecked(True)
        logger.debug("Secret input fields cleared.")