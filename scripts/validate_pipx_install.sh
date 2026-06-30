#!/usr/bin/env bash
set -euo pipefail

print_step() {
  printf '\n==> %s\n' "$1"
}

print_step "Runtime versions"
python3 --version
pipx --version
git --version

print_step "Compile validation"
python3 -m compileall -q hylianscan.py core modules tests

print_step "Unit test validation"
python3 -m unittest discover -s tests -p "test_*.py" -v

print_step "Remove existing pipx installation if present"
pipx uninstall hylianscan || true

print_step "Install current repository with pipx editable mode"
pipx install --editable .

print_step "Validate installed CLI"
which hylianscan
hylianscan --help

print_step "pipx validation completed successfully"
