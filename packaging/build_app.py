#!/usr/bin/env python3
"""Build a standalone FileWarden application.

What you get per platform:

* macOS  — ``dist/FileWarden.app`` (double-clickable, drag it to /Applications);
* Windows — ``dist/FileWarden.exe`` (single file, no Python required);
* Linux  — ``dist/FileWarden`` (single file, no Python required).

The script creates a private build virtualenv (``.build-venv``), installs
PyInstaller there, renders the icon and packages the tkinter GUI.  PyInstaller
can only build for the OS it runs on, so run this script on every platform
you want a binary for.

    python3 packaging/build_app.py                # GUI app
    python3 packaging/build_app.py --with-dnd     # + drag & drop in the GUI
    python3 packaging/build_app.py --cli          # also build the CLI binary
    python3 packaging/build_app.py --clean        # wipe the build venv first
    python3 packaging/build_app.py --python /opt/homebrew/bin/python3.13
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VENV_DIR = REPO / ".build-venv"
DIST_DIR = REPO / "dist"
BUILD_DIR = REPO / "build" / "pyinstaller"
GUI_ENTRY = REPO / "filewarden_gui.py"
CLI_ENTRY = REPO / "filewarden.py"

BUNDLE_ID = "io.github.tyffan1.filewarden"
GUI_NAME = "FileWarden"
CLI_NAME = "filewarden-cli"


def log(message: str) -> None:
    print(f"[build] {message}", flush=True)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    log("$ " + " ".join(str(part) for part in command))
    return subprocess.run(command, check=True, **kwargs)


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def ensure_venv(base_python: str, clean: bool) -> Path:
    if clean and VENV_DIR.exists():
        log(f"removing {VENV_DIR}")
        shutil.rmtree(VENV_DIR)
    python_path = venv_python()
    if not python_path.exists():
        log(f"creating build venv with {base_python}")
        run([base_python, "-m", "venv", str(VENV_DIR)])
    return python_path


def ensure_pyinstaller(python_path: Path, with_dnd: bool) -> None:
    probe = subprocess.run(
        [str(python_path), "-c", "import PyInstaller, sys; print(PyInstaller.__version__)"],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        log("installing PyInstaller into the build venv")
        run([str(python_path), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
        run([str(python_path), "-m", "pip", "install", "--quiet", "pyinstaller"])
    else:
        log(f"PyInstaller {probe.stdout.strip()} already installed")
    if with_dnd:
        probe = subprocess.run(
            [str(python_path), "-c", "import tkinterdnd2"],
            capture_output=True, text=True,
        )
        if probe.returncode != 0:
            log("installing tkinterdnd2 into the build venv")
            run([str(python_path), "-m", "pip", "install", "--quiet", "tkinterdnd2"])


def ensure_icon(explicit: str | None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.exists():
            raise SystemExit(f"icon not found: {path}")
        return path
    if sys.platform == "darwin":
        target = REPO / "build" / f"{GUI_NAME}.icns"
    elif sys.platform == "win32":
        target = REPO / "build" / f"{GUI_NAME}.ico"
    else:
        return None  # no standard icon format on Linux; pass --icon for a custom one
    if target.exists():
        return target
    log("rendering the application icon")
    try:
        from icon import build_icns, build_ico  # noqa: PLC0415 - sibling module, imported lazily

        return build_icns(target) if target.suffix == ".icns" else build_ico(target)
    except Exception as exc:  # pragma: no cover - never block a build over cosmetics
        log(f"icon generation failed ({exc}); continuing without a custom icon")
        return None


def pyinstaller_args(python_path: Path, *, windowed: bool, name: str, icon: Path | None,
                     with_dnd: bool, work_name: str) -> list[str]:
    args = [
        str(python_path), "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", name,
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR / work_name),
        "--specpath", str(BUILD_DIR),
    ]
    if windowed:
        args.append("--windowed")
        if sys.platform == "darwin":
            args += ["--osx-bundle-identifier", BUNDLE_ID]
        if sys.platform != "darwin":
            args.append("--onefile")  # single .exe / bare binary on Windows and Linux
    else:
        args.append("--console")
        args.append("--onefile")
        if sys.platform == "darwin":
            args += ["--osx-bundle-identifier", BUNDLE_ID]
    if icon is not None and sys.platform == "darwin":
        args += ["--icon", str(icon)]
    elif icon is not None and sys.platform == "win32" and icon.suffix == ".ico":
        args += ["--icon", str(icon)]
    if with_dnd:
        args += ["--collect-all", "tkinterdnd2"]
    return args


def adhoc_sign(app_path: Path) -> None:
    if sys.platform != "darwin" or not shutil.which("codesign"):
        return
    try:
        run(["codesign", "--force", "--sign", "-", str(app_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("app signed ad-hoc (fine for local use)")
    except subprocess.CalledProcessError:
        log("ad-hoc signing skipped (codesign failed); the app still runs locally")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable,
                        help="interpreter used to create the build venv")
    parser.add_argument("--name", default=GUI_NAME, help="application name")
    parser.add_argument("--icon", help="custom icon (.icns on macOS, .ico on Windows)")
    parser.add_argument("--with-dnd", action="store_true",
                        help="bundle tkinterdnd2 so drag & drop works in the app")
    parser.add_argument("--cli", action="store_true", help="also build the CLI binary")
    parser.add_argument("--clean", action="store_true", help="remove the build venv first")
    args = parser.parse_args(argv)

    if not GUI_ENTRY.exists() or not CLI_ENTRY.exists():
        raise SystemExit("run this script from the FileWarden source checkout")

    if sys.version_info < (3, 10):
        raise SystemExit("Python 3.10+ is required")

    python_path = ensure_venv(args.python, args.clean)
    ensure_pyinstaller(python_path, args.with_dnd)

    # packaging/icon.py lives next to this file
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    icon = ensure_icon(args.icon)

    log(f"building the GUI application ({sys.platform})")
    run(pyinstaller_args(python_path, windowed=True, name=args.name, icon=icon,
                         with_dnd=args.with_dnd, work_name="gui") + [str(GUI_ENTRY)])

    if args.cli:
        log("building the CLI binary")
        cli_icon = icon if sys.platform == "win32" else None
        run(pyinstaller_args(python_path, windowed=False, name=CLI_NAME, icon=cli_icon,
                             with_dnd=False, work_name="cli") + [str(CLI_ENTRY)])

    log("done. Artifacts:")
    if sys.platform == "darwin":
        app = DIST_DIR / f"{args.name}.app"
        leftover = DIST_DIR / args.name
        if app.exists() and leftover.is_dir():
            log(f"removing the intermediate onedir build ({leftover.name}/); the .app is self-contained")
            shutil.rmtree(leftover)
        adhoc_sign(app)
        log(f"  {app}  — double-click it or drag it to /Applications")
    elif os.name == "nt":
        log(f"  {DIST_DIR / (args.name + '.exe')}  — double-click it")
    else:
        log(f"  {DIST_DIR / args.name}  — run it from the file manager or a terminal")
    if args.cli:
        suffix = ".exe" if os.name == "nt" else ""
        log(f"  {DIST_DIR / (CLI_NAME + suffix)}  — terminal version")
    return 0


if __name__ == "__main__":
    sys.exit(main())
