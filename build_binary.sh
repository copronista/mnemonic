#!/usr/bin/env bash
# Build a standalone Linux binary from mnemonic.py with PyInstaller.
# The result is dist/mnemonic, a self-contained ELF executable: it bundles
# both the Python runtime and english.txt, so it runs with no Python and no
# external files. Only PyInstaller (installed into a throwaway venv) is needed
# at build time.
set -euo pipefail
cd "$(dirname "$0")"

VENV_DIR="${VENV_DIR:-.venv-build}"
PYINSTALLER="$VENV_DIR/bin/pyinstaller"

if [ ! -x "$PYINSTALLER" ]; then
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet pyinstaller
fi

rm -rf build dist
rm -f mnemonic.spec
"$PYINSTALLER" --onefile --name mnemonic --add-data english.txt:. mnemonic.py

rm -rf build
rm -f mnemonic.spec
echo "Built: dist/mnemonic"
