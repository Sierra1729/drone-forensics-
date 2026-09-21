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


def ensure_output_junction(root: Path) -> None:
    """Ensure gui/output links to workspace root output folder so pywebview resolves output assets."""
    gui_output = root / "gui" / "output"
    target_output = root / "output"
    target_output.mkdir(parents=True, exist_ok=True)
    if not gui_output.exists():
        try:
            import os
            import platform
            if platform.system() == "Windows":
                import subprocess
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(gui_output), str(target_output)],
                    capture_output=True,
                    check=False,
                )
            else:
                os.symlink(target_output, gui_output)
        except Exception:
            pass


def main():
    ensure_output_junction(root_dir)
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
