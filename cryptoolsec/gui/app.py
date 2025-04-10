# cryptoolsec/gui/app.py
# -*- coding: utf-8 -*-
"""
GUI application entry point logic for Cryptoolsec.
Contains the function to initialize and run the Qt application.
"""

import sys
import logging

# Import Qt and the MainWindow using relative imports within the package
try:
    print("DEBUG: Importing Qt modules...", file=sys.stderr) # DEBUG PRINT
    from PySide6.QtWidgets import QApplication
    print("DEBUG: Importing MainWindow...", file=sys.stderr) # DEBUG PRINT
    from .main_window import MainWindow # Relative import
    print("DEBUG: Imports successful.", file=sys.stderr) # DEBUG PRINT
except ImportError as e:
     logging.critical(f"GUI App: Failed to import Qt or MainWindow modules: {e}", exc_info=True)
     print(f"Critical Error: Missing required GUI modules (PySide6 or MainWindow). {e}", file=sys.stderr)
     sys.exit(1)
# Import constants for exit codes (assuming this works)
try:
    from ..utils.constants import EXIT_SUCCESS, EXIT_GENERIC_ERROR
except ImportError:
     EXIT_SUCCESS = 0
     EXIT_GENERIC_ERROR = 1


def run():
    """Initializes and runs the Cryptoolsec GUI application."""
    # Configure logging (as before)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stderr, force=True)
    print("DEBUG: run() function started.", file=sys.stderr) # DEBUG PRINT
    logging.info("Starting Cryptoolsec GUI via app.run()...")

    print("DEBUG: Creating QApplication...", file=sys.stderr) # DEBUG PRINT
    app = QApplication(sys.argv)
    print("DEBUG: QApplication created.", file=sys.stderr) # DEBUG PRINT

    try:
        print("DEBUG: Creating MainWindow...", file=sys.stderr) # DEBUG PRINT
        main_window = MainWindow()
        print("DEBUG: MainWindow created.", file=sys.stderr) # DEBUG PRINT

        print("DEBUG: Calling main_window.show()...", file=sys.stderr) # DEBUG PRINT
        main_window.show()
        print("DEBUG: main_window.show() called.", file=sys.stderr) # DEBUG PRINT

    except Exception as e:
         logging.critical(f"Failed to create or show the main window: {e}", exc_info=True)
         print(f"Critical Error: Failed to initialize the main window. Check logs.", file=sys.stderr)
         sys.exit(EXIT_GENERIC_ERROR)

    logging.info("Entering Qt application event loop.")
    print("DEBUG: Calling app.exec()...", file=sys.stderr) # DEBUG PRINT
    exit_code = app.exec()
    # Esta linha abaixo só será impressa APÓS a GUI ser fechada
    print(f"DEBUG: app.exec() finished with code {exit_code}.", file=sys.stderr) # DEBUG PRINT
    logging.info(f"Qt application event loop finished with exit code {exit_code}.")
    sys.exit(exit_code)

# Adicione esta linha no final para permitir rodar 'python -m cryptoolsec.gui.app' para teste
if __name__ == "__main__":
     print("DEBUG: Running app.py as main script (for testing)", file=sys.stderr)
     run()