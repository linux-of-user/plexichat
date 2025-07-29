"""
PlexiChat GUI Interface
Modern PyQt6-based graphical user interface.
"""
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportOptionalMemberAccess=false
# pyright: reportOptionalCall=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportIndexIssue=false
# pyright: reportGeneralTypeIssues=false

import sys
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import PyQt6 first (preferred)
try:
    from PyQt6.QtWidgets import QApplication
    from .main_application_pyqt import PlexiChatGUIPyQt, main as pyqt_main
    PYQT6_AVAILABLE = True
except ImportError as e:
    logger.warning(f"PyQt6 not available: {e}")
    PYQT6_AVAILABLE = False

# Fallback to Tkinter if PyQt6 not available
try:
    from .main_application import PlexiChatGUI
    TKINTER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Tkinter GUI not available: {e}")
    TKINTER_AVAILABLE = False


def run_gui(use_pyqt: bool = True, **kwargs) -> int:
    """
    Run the PlexiChat GUI interface.
    
    Args:
        use_pyqt: Whether to use PyQt6 (True) or Tkinter (False)
        **kwargs: Additional arguments passed to the GUI
    
    Returns:
        Exit code
    """
    try:
        if use_pyqt and PYQT6_AVAILABLE:
            logger.info("Starting PyQt6 GUI interface...")
            return pyqt_main()
        elif TKINTER_AVAILABLE:
            logger.info("Starting Tkinter GUI interface...")
            gui = PlexiChatGUI()
            gui.run()
            return 0
        else:
            logger.error("No GUI framework available!")
            print("Error: No GUI framework available. Please install PyQt6 or ensure Tkinter is available.")
            return 1
            
    except Exception as e:
        logger.error(f"Failed to start GUI: {e}")
        print(f"Error starting GUI: {e}")
        return 1


def get_available_frameworks() -> list:
    """Get list of available GUI frameworks."""
    frameworks = []
    if PYQT6_AVAILABLE:
        frameworks.append("PyQt6")
    if TKINTER_AVAILABLE:
        frameworks.append("Tkinter")
    return frameworks


# Default export
def main():
    """Main entry point for GUI."""
    return run_gui(use_pyqt=True)


# This module should not be run standalone.
# Use 'python run.py gui' to launch the GUI interface.
