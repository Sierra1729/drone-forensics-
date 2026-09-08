"""
gui/main.py

Desktop Entrypoint for PUSHPAK Indigenous Drone Forensics Workstation.
Launches a standalone OS window utilizing Microsoft Edge WebView2 on Windows.
"""

from pathlib import Path
import sys
import webview

# Add workspace root to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from gui.api import DesktopForensicAPI


def main():
    api = DesktopForensicAPI()
    html_path = Path(__file__).resolve().parent / "index.html"

    window = webview.create_window(
        title="PUSHPAK Drone Forensics Workstation (ISO/IEC 27037:2012)",
        url=str(html_path),
        width=1340,
        height=860,
        min_size=(1020, 680),
        js_api=api,
    )

    webview.start(debug=False)


if __name__ == "__main__":
    main()
