#!/usr/bin/env python3
"""
Verificador de paridad 1:1 de opciones rsync (CLI) contra el código C original.

Objetivo:
  - Extraer las opciones de `rsync-original-source-code/options.c` (tabla `long_options[]`)
  - Compararlas con las opciones expuestas por `rsync_phoenix_rebuilt.create_rsync_parser()`

Salida:
  - Conteo total de entradas y option-strings esperadas
  - Faltantes y/o extras (si existen)

Exit code:
  - 0 si hay paridad exacta (sin faltantes ni extras)
  - 1 si hay diferencias
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parent
RSYNC_OPTIONS_C = REPO_ROOT / "rsync-original-source-code" / "options.c"
RSYNC_MANPAGE_MD = REPO_ROOT / "rsync-original-source-code" / "rsync.1.md"


_C_OPT_RE = re.compile(r'\{"(?P<long>[^"]+)"\s*,\s*(?P<short>[^,]+)\s*,')
_HELP_SPLIT_RE = re.compile(r"\s{2,}")
_OPT_TOKEN_RE = re.compile(r"(?P<opt>--?[A-Za-z0-9@][A-Za-z0-9@-]*)")


def _extract_long_options_from_c(path: Path) -> List[Tuple[str, Optional[str], int]]:
    """Return [(long_name, short_char_or_None, c_line_number), ...] from long_options[] table."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    start_idx = None
    end_idx = None
    for i, line in enumerate(lines):
        if "static struct poptOption long_options[]" in line:
            start_idx = i
            continue
        if start_idx is not None and line.strip().startswith("{0,0,0,0"):
            end_idx = i
            break

    if start_idx is None or end_idx is None or end_idx <= start_idx:
        raise RuntimeError("No se pudo localizar la tabla long_options[] en options.c")

    out: List[Tuple[str, Optional[str], int]] = []
    for i in range(start_idx, end_idx):
        m = _C_OPT_RE.search(lines[i])
        if not m:
            continue
        long_name = m.group("long")
        short_raw = m.group("short").strip()
        if short_raw == "0":
            short = None
        else:
            short = short_raw.strip().strip("'")
        out.append((long_name, short, i + 1))
    return out


def _expected_option_strings(c_opts: Iterable[Tuple[str, Optional[str], int]]) -> Set[str]:
    expected: Set[str] = set()
    for long_name, short, _line in c_opts:
        expected.add(f"--{long_name}")
        if short is not None:
            expected.add(f"-{short}")
    return expected


def _python_option_strings() -> Set[str]:
    import rsync_phoenix_rebuilt as impl

    parser = impl.create_rsync_parser()
    found: Set[str] = set()
    for action in parser._actions:
        for opt in action.option_strings:
            found.add(opt)
    return found


def _extract_help_rsync_block_lines(path: Path) -> List[str]:
    """Extract the code block under the `[comment]: # (help-rsync.h)` marker."""
    return _extract_help_block_lines(path, "help-rsync.h")

def _extract_help_rsyncd_block_lines(path: Path) -> List[str]:
    """Extract the code block under the `[comment]: # (help-rsyncd.h)` marker."""
    return _extract_help_block_lines(path, "help-rsyncd.h")

def _extract_help_block_lines(path: Path, marker: str) -> List[str]:
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    marker_idx = None
    for i, line in enumerate(text):
        if line.strip() == f"[comment]: # ({marker})":
            marker_idx = i
            break
    if marker_idx is None:
        raise RuntimeError(f"No se encontró el marcador {marker} en rsync.1.md")

    # Find next fenced code block.
    i = marker_idx
    while i < len(text) and text[i].strip() != "```":
        i += 1
    if i >= len(text):
        raise RuntimeError(f"No se encontró el inicio del code block {marker} en rsync.1.md")
    i += 1  # skip opening fence

    lines: List[str] = []
    while i < len(text) and text[i].strip() != "```":
        lines.append(text[i].rstrip("\n"))
        i += 1
    if i >= len(text):
        raise RuntimeError(f"No se encontró el cierre del code block {marker} en rsync.1.md")
    return lines


def _extract_option_strings_from_help_block(lines: Sequence[str]) -> Set[str]:
    """Extract normalized option strings (e.g. `--suffix`, `-v`) from help summary lines."""
    out: Set[str] = set()
    for line in lines:
        if not line.strip():
            continue
        parts = _HELP_SPLIT_RE.split(line.strip(), maxsplit=1)
        lhs = parts[0]
        for raw in re.split(r"[,\s]+", lhs):
            if not raw or not raw.startswith("-"):
                continue
            m = _OPT_TOKEN_RE.match(raw)
            if not m:
                continue
            opt = m.group("opt")
            # The help summary contains the meta-placeholder `--no-OPTION`, which is not
            # a literal option-string in the parser (rsync accepts any `--no-FOO`).
            if opt == "--no-OPTION":
                continue
            out.add(opt)
    return out


def _expected_help_text_from_manpage(help_lines: Sequence[str]) -> str:
    # Match the footer printed by rsync's usage.c after help-rsync.h.
    footer_lines = [
        'Use "rsync --daemon --help" to see the daemon-mode command-line options.',
        "Please see the rsync(1) and rsyncd.conf(5) manpages for full documentation.",
        "See https://rsync.samba.org/ for updates, bug reports, and answers",
    ]
    return "\n".join(help_lines) + "\n\n" + "\n".join(footer_lines) + "\n"


def _expected_daemon_help_text_from_manpage(help_lines: Sequence[str]) -> str:
    footer_lines = [
        "If you were not trying to invoke rsync as a daemon, avoid using any of the",
        "daemon-specific rsync options.  See also the rsyncd.conf(5) manpage.",
    ]
    return "\n".join(help_lines) + "\n\n" + "\n".join(footer_lines) + "\n"


def main() -> int:
    if not RSYNC_OPTIONS_C.exists():
        print(f"ERROR: no existe `{RSYNC_OPTIONS_C}`", file=sys.stderr)
        return 1
    if not RSYNC_MANPAGE_MD.exists():
        print(f"ERROR: no existe `{RSYNC_MANPAGE_MD}`", file=sys.stderr)
        return 1

    c_opts = _extract_long_options_from_c(RSYNC_OPTIONS_C)
    help_lines = _extract_help_rsync_block_lines(RSYNC_MANPAGE_MD)
    daemon_help_lines = _extract_help_rsyncd_block_lines(RSYNC_MANPAGE_MD)

    # Expected parser option strings are those from options.c plus the aliases shown in the
    # help summary block (e.g. -D/-F/-P), which are real rsync options but not in long_options[].
    expected = _expected_option_strings(c_opts) | _extract_option_strings_from_help_block(help_lines)
    found = _python_option_strings()

    missing = sorted(expected - found)
    extra = sorted(found - expected)

    # Help-text parity (help-rsync.h generated from rsync.1.md)
    import rsync_phoenix_rebuilt as impl
    expected_help = _expected_help_text_from_manpage(help_lines)
    help_ok = impl.RSYNC_OPTIONS_HELP_TEXT == expected_help
    expected_daemon_help = _expected_daemon_help_text_from_manpage(daemon_help_lines)
    daemon_help_ok = impl.RSYNC_DAEMON_OPTIONS_HELP_TEXT == expected_daemon_help

    print("=" * 80)
    print("REPORTE DE PARIDAD 1:1 DE OPCIONES (options.c vs create_rsync_parser)".center(80))
    print("=" * 80)
    print()
    print(f"Entradas en C (long_options[]):      {len(c_opts)}")
    print(f"Option strings esperadas (C):        {len(expected)}")
    print(f"Option strings encontradas (Python): {len(found)}")
    print()

    if missing:
        print(f"❌ FALTANTES EN PYTHON: {len(missing)}")
        for opt in missing:
            print(f"  - {opt}")
        print()
    else:
        print("✅ FALTANTES EN PYTHON: 0")
        print()

    if extra:
        print(f"⚠️  EXTRAS EN PYTHON (no están en options.c): {len(extra)}")
        for opt in extra:
            print(f"  - {opt}")
        print()
    else:
        print("✅ EXTRAS EN PYTHON: 0")
        print()

    print(f"Paridad help-rsync.h (rsync.1.md):   {'OK' if help_ok else 'NO'}")
    print(f"Paridad help-rsyncd.h (rsync.1.md):  {'OK' if daemon_help_ok else 'NO'}")
    ok = (not missing) and (not extra) and help_ok and daemon_help_ok
    print(f"PARIDAD 1:1: {'OK' if ok else 'NO'}")
    if not help_ok:
        # Show first mismatch line to keep output short.
        exp_lines = expected_help.splitlines()
        got_lines = impl.RSYNC_OPTIONS_HELP_TEXT.splitlines()
        for idx in range(max(len(exp_lines), len(got_lines))):
            exp = exp_lines[idx] if idx < len(exp_lines) else "<EOF>"
            got = got_lines[idx] if idx < len(got_lines) else "<EOF>"
            if exp != got:
                print(f"\nPrimera diferencia help (línea {idx+1}):")
                print(f"  esperado: {exp!r}")
                print(f"  actual:   {got!r}")
                break
    if not daemon_help_ok:
        exp_lines = expected_daemon_help.splitlines()
        got_lines = impl.RSYNC_DAEMON_OPTIONS_HELP_TEXT.splitlines()
        for idx in range(max(len(exp_lines), len(got_lines))):
            exp = exp_lines[idx] if idx < len(exp_lines) else "<EOF>"
            got = got_lines[idx] if idx < len(got_lines) else "<EOF>"
            if exp != got:
                print(f"\nPrimera diferencia daemon help (línea {idx+1}):")
                print(f"  esperado: {exp!r}")
                print(f"  actual:   {got!r}")
                break
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
