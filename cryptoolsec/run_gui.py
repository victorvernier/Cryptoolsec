#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main entry point script to launch the Cryptoolsec GUI application.
"""

import sys
import logging
from PySide6.QtWidgets import QApplication

# Importa a classe da janela principal do nosso pacote GUI
# Assume que o diretório pai de 'cryptoolsec/' está no PYTHONPATH
# ou que o pacote foi instalado.
try:
    from cryptoolsec.gui.main_window import MainWindow
except ImportError as e:
    # Tenta um caminho relativo se o módulo não for encontrado (para execução local simples)
    try:
        sys.path.append('.') # Adiciona diretório atual ao path
        from cryptoolsec.gui.main_window import MainWindow
    except ImportError:
         print(f"Error: Could not import MainWindow. Ensure the package structure is correct and dependencies are installed.", file=sys.stderr)
         print(f"Details: {e}", file=sys.stderr)
         sys.exit(1)


if __name__ == "__main__":
    # Configuração básica de logging para a GUI (pode ser mais elaborada depois)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stderr)
    logging.info("Starting Cryptoolsec GUI...")

    # Cria a aplicação Qt
    app = QApplication(sys.argv)

    # Cria e exibe a janela principal
    main_window = MainWindow()
    main_window.show()

    # Inicia o loop de eventos da aplicação
    logging.info("Entering Qt application event loop.")
    sys.exit(app.exec())