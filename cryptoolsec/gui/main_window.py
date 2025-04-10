# cryptoolsec/gui/main_window.py
# -*- coding: utf-8 -*-
"""Defines the main window (View) for the Cryptoolsec GUI application."""

import logging
import sys
import importlib.resources # For loading package resources like icons
from pathlib import Path     # For path manipulation with importlib.resources

# --- Qt Imports ---
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QMessageBox, QProgressBar
)
from PySide6.QtGui import QIcon # For window icon
from PySide6.QtCore import Slot # Although slots are now mainly in Controller

# --- Local Imports ---
# Using TYPE_CHECKING for AppController hint avoids circular import issues at runtime
from typing import TYPE_CHECKING
try:
    if TYPE_CHECKING:
        from .controller import AppController # Only for type checker

    from .file_selectors_widget import FileSelectorsWidget
    from .secret_input_widget import SecretInputWidget
    # Controller is imported for instantiation
    from .controller import AppController
except ImportError as e:
     # Fallback logic (consider removing if using editable install reliably)
     if '.' not in sys.path: sys.path.append('.')
     logging.warning("MainWindow: Using fallback import path for GUI components.")
     # Need to redefine TYPE_CHECKING import if using fallback path
     from typing import TYPE_CHECKING # Redundant but safe in except block
     if TYPE_CHECKING:
         from cryptoolsec.gui.controller import AppController

     from cryptoolsec.gui.file_selectors_widget import FileSelectorsWidget
     from cryptoolsec.gui.secret_input_widget import SecretInputWidget
     from cryptoolsec.gui.controller import AppController


logger = logging.getLogger(__name__) # Module-specific logger

class MainWindow(QMainWindow):
    """
    Main application window - acts primarily as the View.
    It holds the main widgets, connects actions to the controller,
    and provides methods for the controller to update the UI.
    """

    def __init__(self, parent: QWidget | None = None):
        """Initializes the main window, UI components, controller, styles, and icon."""
        super().__init__(parent)
        self.setWindowTitle("Cryptoolsec")
        self.setGeometry(100, 100, 600, 400) # Adjusted size

        # --- Instantiate UI Components ---
        # These are the main building blocks of the UI
        self.file_selectors = FileSelectorsWidget(self)
        self.secret_input = SecretInputWidget(self)
        self.progress_bar = QProgressBar(self)
        self.encrypt_button = QPushButton("Encrypt", self)
        self.decrypt_button = QPushButton("Decrypt", self)

        # --- Instantiate Controller ---
        # The controller manages the application logic triggered by the UI
        self.controller = AppController(self, self.file_selectors, self.secret_input, self)

        # --- Build UI Layout ---
        self._init_ui()

        # --- Apply Visual Styles ---
        self._apply_styles()

        # --- Set Window Icon ---
        self._set_window_icon()

        logging.info("MainWindow initialized successfully.")

    def _init_ui(self):
        """Sets up the UI layout by arranging the main widgets."""
        logging.debug("Initializing main window UI layout...")

        # Central widget acts as a container for the layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)

        # Add the custom widgets and progress bar
        main_layout.addWidget(self.file_selectors)
        main_layout.addWidget(self.secret_input)
        main_layout.addWidget(self.progress_bar)

        # Configure progress bar appearance
        self.progress_bar.setVisible(False) # Start hidden
        self.progress_bar.setRange(0, 100)   # Default to percentage
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True) # Show percentage text

        # Spacer pushes buttons to the bottom
        main_layout.addStretch(1)

        # Horizontal layout for action buttons (aligned to the right)
        action_layout = QHBoxLayout()
        action_layout.addStretch(1) # Spacer before buttons
        action_layout.addWidget(self.encrypt_button)
        action_layout.addWidget(self.decrypt_button)
        main_layout.addLayout(action_layout) # Add button layout to main layout

        # --- Connect Signals to Controller ---
        # Button clicks are directly connected to the controller's public slots
        self.encrypt_button.clicked.connect(self.controller.start_encryption)
        self.decrypt_button.clicked.connect(self.controller.start_decryption)

        logging.debug("Main window UI layout finished.")

    def _apply_styles(self):
        """Applies basic application-wide QSS styling."""
        logging.debug("Applying styles...")
        # Defined color palette: Grays/Blues, Green progress, subtle translucency
        style_sheet = """
            QMainWindow { background-color: #E8EFF5; /* Light grayish blue */ }
            QWidget { color: #1F1F1F; /* Dark text for light theme */ }
            QGroupBox {
                font-weight: bold; border: 1px solid #B0C4DE; /* Light Steel Blue border */
                border-radius: 5px; margin-top: 10px; padding: 10px 5px 5px 5px;
                /* Semi-transparent background */
                background-color: rgba(210, 220, 235, 200); /* Lighter blue/gray, ~78% opaque */
            }
            QGroupBox::title {
                subcontrol-origin: margin; subcontrol-position: top left;
                padding: 0 3px 0 3px; color: #2E4A6E; /* Dark Slate Gray/Blue */
            }
            QPushButton {
                background-color: #6C8EBF; /* Medium Blue */
                color: white; border: 1px solid #5A7FAF; /* Darker blue border */
                padding: 5px 15px; border-radius: 3px; min-height: 20px;
            }
            QPushButton:hover { background-color: #7F9DD1; /* Lighter blue on hover */ }
            QPushButton:pressed { background-color: #5A7FAF; /* Darker blue when pressed */ }
            QPushButton:disabled { background-color: #B0B0B0; color: #707070; border-color: #A0A0A0; }
            QLineEdit {
                border: 1px solid #B0C4DE; padding: 4px; border-radius: 3px;
                background-color: #FFFFFF; /* White background */
            }
            QLineEdit:read-only { background-color: #F0F0F0; /* Light gray for read-only */ }
            QProgressBar {
                border: 1px solid #B0C4DE; border-radius: 3px; text-align: center;
                background-color: #FFFFFF; height: 20px;
            }
            QProgressBar::chunk {
                background-color: #50C878; /* Emerald Green */
                border-radius: 3px;
            }
            QLabel { color: #1F1F1F; /* Ensure labels are dark */ }
        """
        try:
            self.setStyleSheet(style_sheet)
            logger.debug("Styles applied successfully.")
        except Exception as e:
             logger.error(f"Failed to apply styles: {e}", exc_info=True)

    def _set_window_icon(self):
        """
        Loads and sets the application window icon based on the operating system,
        looking for icon files within the 'cryptoolsec.assets' package.
        """
        icon_set = False
        icon_filename = None
        platform = sys.platform

        try:
            # Determine preferred icon filename based on OS
            if platform == "win32": icon_filename = "icon.ico"
            elif platform == "darwin": icon_filename = "icon.icns" # macOS
            else: icon_filename = "icon.png" # Linux and others default to PNG

            if icon_filename:
                logger.debug(f"Attempting to load icon for platform '{platform}': {icon_filename}")
                try:
                    # Use importlib.resources (requires Python 3.9+)
                    # Assumes 'assets' is a sub-package of 'cryptoolsec'
                    assets_path_ref = importlib.resources.files('cryptoolsec.assets')
                    icon_file_path = assets_path_ref.joinpath(icon_filename)

                    # Need to check existence using the traversable API
                    if icon_file_path.is_file():
                        # QIcon needs a string path
                        app_icon = QIcon(str(icon_file_path))
                        self.setWindowIcon(app_icon)
                        icon_set = True
                        logger.info(f"Window icon set successfully from: {icon_file_path}")
                    else:
                        logger.warning(f"Preferred icon '{icon_filename}' not found via importlib.resources.")
                        # Optional: Implement fallback logic (e.g., try loading icon.png if .ico/.icns failed)
                        if icon_filename != "icon.png":
                            logger.debug("Trying .png fallback...")
                            icon_file_path = assets_path_ref.joinpath("icon.png")
                            if icon_file_path.is_file():
                                app_icon = QIcon(str(icon_file_path))
                                self.setWindowIcon(app_icon)
                                icon_set = True
                                logger.info(f"Window icon set from PNG fallback: {icon_file_path}")

                except ModuleNotFoundError:
                    logger.error("Could not locate assets directory via importlib.resources. Is 'cryptoolsec.assets' a package with __init__.py?")
                except Exception as e:
                    logger.error(f"Failed to load or set icon '{icon_filename}': {e}", exc_info=True)

            if not icon_set:
                 logger.error("Window icon could not be set.")

        except Exception as e:
            logger.error(f"Unexpected error in _set_window_icon: {e}", exc_info=True)

    # --- Methods for Controller to Update UI ---
    # (These methods remain as previously reviewed and corrected)
    def show_message(self, title: str, message: str, level: str = "info"):
        """Displays a modal message box to the user."""
        logger.debug(f"Showing message box ({level}): Title='{title}', Message='{message[:100]}...'")
        if level == "warning": QMessageBox.warning(self, title, message)
        elif level == "error" or level == "critical": QMessageBox.critical(self, title, message)
        else: QMessageBox.information(self, title, message)

    def update_progress(self, value: int):
        """Updates the progress bar. Handles percentage or indeterminate state."""
        if not self.progress_bar.isVisible(): self.progress_bar.setVisible(True)
        if value < 0: # Indeterminate
            if self.progress_bar.minimum() != 0 or self.progress_bar.maximum() != 0: self.progress_bar.setRange(0, 0)
            logger.debug("Progress bar set to indeterminate mode.")
        else: # Percentage
            if self.progress_bar.minimum() != 0 or self.progress_bar.maximum() != 0: self.progress_bar.setRange(0, 100)
            progress_val = max(0, min(value, 100))
            self.progress_bar.setValue(progress_val)
            logger.debug(f"Progress bar updated to {progress_val}%")

    def set_ui_busy(self, busy: bool):
        """Disables/Enables main UI elements during background operations."""
        logging.debug(f"Setting UI busy state to: {busy}")
        is_enabled = not busy
        # Enable/disable widgets
        if self.file_selectors: self.file_selectors.setEnabled(is_enabled)
        if self.secret_input: self.secret_input.setEnabled(is_enabled)
        if self.encrypt_button: self.encrypt_button.setEnabled(is_enabled)
        if self.decrypt_button: self.decrypt_button.setEnabled(is_enabled)
        # Manage progress bar
        if busy:
            self.progress_bar.setRange(0, 100) # Ensure determinate for start
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
        else:
            # Keep final state visible (set by _operation_finished)
            pass