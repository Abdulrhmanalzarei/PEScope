import argparse
import logging
import sys

from . import __version__
from .config import load_config
from .errors import PEScopeError
from .logging_utils import setup_logging
from .pe import (
    parse,
    entropy,
    section_data,
    imports,
    ascii_strings,
    security_indicators,
    MACHINE_NAMES,
)


def build_parser():
    p = argparse.ArgumentParser(
        prog="pescope",
        description="Pure Python Windows PE analyzer",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"PEScope {__version__}",
    )
    p.add_argument("--config", help="Path to JSON configuration file")
    p.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    sub = p.add_subparsers(dest="command")

    for name, help_text in [
        ("info", "Show PE header information"),
        ("sections", "Show PE sections"),
        ("imports", "Show imported DLLs and APIs"),
        ("strings", "Extract ASCII strings"),
        ("analyze", "Run a basic security analysis"),
    ]:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("file")
        if name == "strings":
            cmd.add_argument("--min-length", type=int, default=None)

    return p


def show_info(pe):
    print("PEScope")
    print("=" * 40)
    print(f"File       : {pe.path}\nSize       : {len(pe.data)} bytes")
    print(f"Machine    : {MACHINE_NAMES.get(pe.machine, hex(pe.machine))}")
    print(f"Format     : {('PE32+' if pe.is_64 else 'PE32')}")
    print(
        f"Entry Point: 0x{pe.entry_point:08X}\n"
        f"Image Base : 0x{pe.image_base:X}"
    )
    print(f"Sections   : {len(pe.sections)}")
    print(
        f"Alignment  : section={pe.section_alignment}, "
        f"file={pe.file_alignment}"
    )


def show_sections(pe):
    print(
        f"{'NAME':<10} {'RVA':<12} {'V.SIZE':<12} "
        f"{'RAW SIZE':<12} {'RAW OFF':<12} ENTROPY"
    )
    print("-" * 78)

    for s in pe.sections:
        print(
            f"{s.name:<10} 0x{s.virtual_address:08X}  "
            f"{s.virtual_size:<12} {s.raw_size:<12} 0x{s.raw_offset:08X}  "
            f"{entropy(section_data(pe, s)):.2f}"
        )


def show_imports(pe):
    items = imports(pe)

    if not items:
        print("No imports found or import table could not be resolved.")
        return

    for dll, apis in items:
        print(f"\n{dll}")
        for api in apis:
            print(f"  {api}")


def show_strings(pe, minimum):
    if minimum < 1:
        raise ValueError("minimum string length must be positive")

    items = ascii_strings(pe.data, minimum)
    print(f"Found {len(items)} ASCII strings (minimum length={minimum}):")

    for off, value in items[:500]:
        print(f"0x{off:08X}  {value}")


def show_analysis(pe, threshold):
    api_hits, entropy_hits = security_indicators(
        pe,
        imports(pe),
        threshold,
    )

    print("Security Analysis")
    print("=" * 40)
    print("\nIndicators:")

    for api in api_hits:
        print(f"  [!] API indicator: {api}")

    for name in entropy_hits:
        print(f"  [!] High entropy section: {name}")

    if not api_hits and (not entropy_hits):
        print("  No configured indicators found.")

    print("\nImportant: indicators are NOT proof of malware.")


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.command:
        build_parser().print_help()
        return

    try:
        config = load_config(args.config)
        setup_logging(args.log_level)
        logging.getLogger("pescope").debug(
            "Configuration loaded: %s",
            config,
        )
        pe = parse(args.file)

        if args.command == "info":
            show_info(pe)
        elif args.command == "sections":
            show_sections(pe)
        elif args.command == "imports":
            show_imports(pe)
        elif args.command == "strings":
            show_strings(pe, args.min_length or config["min_string_length"])
        elif args.command == "analyze":
            show_analysis(pe, config["entropy_threshold"])

    except (PEScopeError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
