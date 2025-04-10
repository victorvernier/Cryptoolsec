# cryptoolsec/gui/file_selectors_widget.py
# -*- coding: utf-8 -*-
"""Custom widget for selecting input and output files."""

import logging
import os
import sys
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog
)
from PySide6.QtCore import Slot

logger = logging.getLogger(__name__)

class FileSelectorsWidget(QWidget):
    """
    Widget containing input/output file selection fields and buttons.
    Provides methods to retrieve selected paths and clear them.
    Suggests output filename based on input filename extension.
    """

    def __init__(self, parent: QWidget | None = None):
        """Initializes the file selectors widget."""
        super().__init__(parent)
        self._input_path: str | None = None
        self._output_path: str | None = None
        self.input_path_edit: QLineEdit | None = None
        self.output_path_edit: QLineEdit | None = None
        self._init_ui()

    def _init_ui(self):
        """Initialize the UI elements for this widget."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Input Row (unchanged)
        input_layout = QHBoxLayout()
        input_label = QLabel("Input File:", self)
        self.input_path_edit = QLineEdit(self)
        self.input_path_edit.setPlaceholderText("Select input file")
        self.input_path_edit.setReadOnly(True)
        input_browse_button = QPushButton("Select...", self)
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_path_edit, 1)
        input_layout.addWidget(input_browse_button)
        layout.addLayout(input_layout)

        # Output Row (unchanged layout, logic in slot)
        output_layout = QHBoxLayout()
        output_label = QLabel("Output File:", self)
        self.output_path_edit = QLineEdit(self)
        self.output_path_edit.setPlaceholderText("Select output file path")
        self.output_path_edit.setReadOnly(True)
        output_browse_button = QPushButton("Select...", self)
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_path_edit, 1)
        output_layout.addWidget(output_browse_button)
        layout.addLayout(output_layout)

        # Connect signals (unchanged)
        input_browse_button.clicked.connect(self._select_input_file)
        output_browse_button.clicked.connect(self._select_output_file)

    @Slot()
    def _select_input_file(self):
        """Opens a QFileDialog to select the input file."""
        # Unchanged from previous version
        start_dir = os.path.dirname(self._input_path) if self._input_path else os.path.expanduser("~")
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Input File", start_dir, "All Files (*.*)")
        if file_path:
            # Clear output path when input changes to avoid mismatches
            self.clear_output()
            self._input_path = file_path
            self.input_path_edit.setText(file_path)
            logger.info(f"Input file selected: {file_path}")

    # --- METHOD MODIFIED ---
    @Slot()
    def _select_output_file(self):
        """
        Opens a QFileDialog to select the output file path.
        Suggests a filename based on the input file:
        - If input is 'file.ext', suggests 'file.ext.enc'.
        - If input is 'file.ext.enc', suggests 'file.ext'.
        """
        start_dir = os.path.dirname(self._output_path) if self._output_path else (os.path.dirname(self._input_path) if self._input_path else os.path.expanduser("~"))
        suggested_filename = ""

        if self._input_path:
            base_input_name = os.path.basename(self._input_path)
            name_part, ext_part = os.path.splitext(base_input_name)

            if ext_part.lower() == '.enc':
                # Input has .enc -> Suggest name without .enc (for decryption output)
                suggested_filename = name_part
                logger.debug(f"Suggesting decryption output filename: {suggested_filename}")
            else:
                # Input does not have .enc -> Suggest name + .enc (for encryption output)
                suggested_filename = base_input_name + ".enc"
                logger.debug(f"Suggesting encryption output filename: {suggested_filename}")

        # Combine starting directory with the suggested filename
        start_path = os.path.join(start_dir, suggested_filename)

        # Set appropriate filters depending on expected output
        if suggested_filename.endswith(".enc"):
             filters = "Encrypted Files (*.enc);;All Files (*.*)"
        else:
             filters = "All Files (*.*);;Encrypted Files (*.enc)" # Prioritize All Files for decrypted output

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Select Output File Path",
            start_path, # Pass suggested name/path here
            filters
            )
        if file_path:
            # Extra check: If user saves with .enc but suggestion didn't have it, maybe warn? Or just accept user choice. Accept for now.
            # if not suggested_filename.endswith(".enc") and file_path.lower().endswith(".enc"):
            #    logger.warning("User saved decrypted file with .enc extension.")
            self._output_path = file_path
            self.output_path_edit.setText(file_path)
            logger.info(f"Output file selected: {file_path}")
    # --- END OF MODIFIED METHOD ---

    # Public access methods (unchanged)
    def get_input_path(self) -> str | None: return self._input_path
    def get_output_path(self) -> str | None: return self._output_path

    # Clear methods (unchanged)
    @Slot()
    def clear_input(self):
        self._input_path = None
        if self.input_path_edit: self.input_path_edit.clear()
        logger.debug("Input path cleared.")

    @Slot()
    def clear_output(self):
        self._output_path = None
        if self.output_path_edit: self.output_path_edit.clear()
        logger.debug("Output path cleared.")

    @Slot()
    def clear_all(self):
        self.clear_input()
        self.clear_output()