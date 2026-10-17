# FileWarden

Scan files and folders via the VirusTotal API — hash-first, no silent uploads.

FileWarden checks files and folders with VirusTotal and ships in two flavors: a
terminal tool and a tkinter GUI. It is written against the Python standard
library only (`urllib`, `hashlib`, `tkinter`) — no mandatory dependencies, and
nothing is ever sent anywhere except VirusTotal.

## How it works

1. The file is read locally and hashed (SHA-256). Nothing leaves your machine.
2. VirusTotal is asked for a report on that hash — a single `GET /files/{sha256}` request.
3. If the hash is already known, the verdict is shown right away and the file is never uploaded.
4. If the hash is unknown, FileWarden asks for permission to upload, once per file
   (`y/n/a/q` in the CLI, a dialog with buttons in the GUI). Only after an explicit
   confirmation is the file sent to VirusTotal.
5. After the upload it waits for the analysis to finish and reports the verdict.

Why hash-first: files uploaded to VirusTotal become available to researchers and
vendors, which is unacceptable for personal or confidential documents. Hash
lookups are also much faster and cheaper on the API quota. Automatic uploads are
possible only as an explicit opt-in — the `--upload always` flag or a GUI setting.

## Requirements

* Python 3.10+ with tkinter (bundled in the python.org installers; on Linux you
  may need the `python3-tk` package).
* Windows, macOS or Linux.
* Drag & drop in the GUI is optional: `pip install tkinterdnd2`. Without it the
  “File…”, “Folder…” and “Browse…” buttons cover the same workflow.

## Installation

The easiest path is to put the `filewarden` and `filewarden-gui` commands on your
PATH with pipx, so that a scan is just `filewarden ~/Downloads`:

```console
pipx install --editable .    # code edits take effect immediately, no reinstall
pipx install --force .       # regular (copied) install, if editable is not desired
pipx install ".[dnd]"        # regular install + drag & drop in the GUI
```

Without pipx you can use `python3 -m pip install --user .` or symlink the
launchers into a directory on PATH (they are executable and locate the package
themselves):

```console
ln -s "$PWD/filewarden.py"     ~/.local/bin/filewarden
ln -s "$PWD/filewarden_gui.py" ~/.local/bin/filewarden-gui
```

Running straight from a source checkout works too, with no installation at all:

```console
python3 filewarden.py --help        # terminal version
python3 filewarden_gui.py           # graphical version
```

## Building a standalone app

`packaging/build_app.py` produces a double-clickable application that does not
require Python to be installed (PyInstaller under the hood):

```console
python3 packaging/build_app.py                # GUI app
python3 packaging/build_app.py --with-dnd     # + drag & drop inside the app
python3 packaging/build_app.py --cli          # also build the CLI binary
python3 packaging/build_app.py --clean        # rebuild the build venv from scratch
```

| Platform | Result |
| --- | --- |
| macOS | `dist/FileWarden.app` — double-click it or drag it to `/Applications` |
| Windows | `dist/FileWarden.exe` — single file, just run it |
| Linux | `dist/FileWarden` — single file, just run it |

Notes:

* the script creates a private build venv in `.build-venv` and installs
  PyInstaller there; the app itself stays dependency-free;
* the application icon is generated procedurally (`packaging/icon.py`), so no
  image assets are needed and you can tweak the colours/shape in code;
* macOS builds are ad-hoc signed, which is fine for local use; distributing the
  app to other machines requires Developer ID signing and notarization,
  otherwise Gatekeeper will warn (right-click → Open still works);
* PyInstaller can only build for the OS it runs on — run the script on Windows
  to get a `.exe`, on Linux to get a Linux binary;
* a ready-made GitHub Actions workflow (`.github/workflows/build.yml`) builds
  the Windows `.exe` and the Linux binary on GitHub runners — *Actions →
  Build apps → Run workflow*, no local Windows machine needed.

## API key

Get a free key at <https://www.virustotal.com/gui/my-apikey>.

The key is resolved in this order:

1. `-k/--api-key KEY` — for the current run only;
2. `VIRUSTOTAL_API_KEY` (or `VT_API_KEY`) — environment variable;
3. `filewarden --set-key KEY` — saved to the config file with `0600` permissions:
   * Linux/macOS: `~/.config/filewarden/config.json`
   * Windows: `%APPDATA%\filewarden\config.json`

In the GUI the key is entered under Settings → API key, with a “Check key”
button right there.

## Terminal version

```console
filewarden ~/Downloads                      # recursive, asks before each upload
filewarden ~/Documents --upload never       # hash lookups only, no uploads at all
filewarden ~/iso --upload always --rpm 4    # automatic uploads (explicit consent)
filewarden . --exclude "*.log" --exclude "node_modules" -v
filewarden ~/data --json report.json --csv report.csv --quiet
```

If the command is not installed, the same examples work as `python3 filewarden.py …`.
Settings from `~/.config/filewarden/config.json` are picked up automatically, so
after a one-time `filewarden --set-key KEY` you can simply run `filewarden PATH`.

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--upload never\|ask\|always` | upload policy for unknown files (default `ask`) |
| `--rpm N` | API request rate limit per minute (public API: 4) |
| `--max-upload-mb N` | maximum file size to upload (default 32 MB) |
| `--exclude GLOB` | skip files by pattern (repeatable) |
| `--follow-symlinks` | do not skip symbolic links |
| `--analysis-timeout SEC` | how long to wait for an analysis after an upload |
| `--json FILE`, `--csv FILE` | reports for automation and Excel |
| `-v`, `-q`, `--no-color` | verbose / quiet / monochrome output |

Subfolders are always walked recursively; duplicate paths are not scanned twice;
symlink cycles cannot loop the walk.

Exit codes: `0` — clean, `1` — malicious or suspicious files found,
`2` — error (key, network, bad path), `130` — interrupted by the user.

## Graphical version

```console
filewarden-gui            # launch
filewarden-gui --check    # diagnostics without opening a window
```

* Drag files and folders right into the window (with `tkinterdnd2` installed) or
  add them with “File…”, “Folder…”, “Browse…”.
* The “Ask before uploading files missing from VirusTotal” checkbox is enabled by
  default; the dialog warns that the file will become available to researchers.
* Double-clicking a row opens the VirusTotal report in the browser; the context
  menu offers “Reveal in folder”, “Copy SHA-256”, “Copy path”.
* The table shows size, verdict, detection count, hash and a note; rows are
  color-coded by verdict, with progress and counters at the bottom.
* “Save report…” exports JSON or CSV.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| **malicious** | at least one engine reported `malicious` |
| **suspicious** | at least one engine reported `suspicious` |
| **clean** | no detections |
| **not in VT** | hash is unknown, no upload took place |
| **oversized** | hash is unknown and the file is above the upload limit |
| **error** | the file could not be read or the API request failed |

## VirusTotal limits

* Public (free) key: 4 requests per minute, 500 per day, 15,500 per month;
  API uploads are capped at 32 MB.
* Premium key: higher limits and uploads up to 650 MB — set `--rpm N` or raise
  the limit in the settings, and increase `--max-upload-mb` for large files.
* One file costs at least one request, so 100 files take ~25 minutes on a free
  key; FileWarden prints a time estimate before it starts.
* HTTP `429` responses are handled automatically: retries with backoff
  (honoring `Retry-After`) and a clear message when the quota is exhausted.

## Reports

JSON: `tool`, `version`, `generated_at`, `meta`, `summary` (counters) and
`results` (path, size, `sha256`, `status`, engine stats, detection list,
`uploaded`, report link, note). CSV carries the same key fields and opens in
Excel (UTF-8 with BOM).

## Tests

```console
python3 -m unittest discover -s tests -t .
```

47 tests, all offline: the API client is tested through an injectable
transport, and the CLI runs end-to-end against a local mock of the VirusTotal
API (hash cache, uploads, analysis polling, exit codes, reports).

## Limitations and security notes

* This is not a replacement for antivirus software: a VirusTotal verdict is the
  aggregated opinion of many engines, and “clean” is not a guarantee.
* An uploaded file becomes available to vendors and researchers — never upload
  personal documents, keys or private correspondence.
* The file being uploaded is read into memory as a whole (up to
  `--max-upload-mb`); keep an eye on RAM for hundreds-of-megabytes files on servers.
* The API key is stored locally with owner-only permissions and is never sent
  anywhere except `virustotal.com`.

## License

MIT — see [LICENSE](LICENSE).
