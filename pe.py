import math
import struct
from collections import Counter
from dataclasses import dataclass, field

from .errors import PEFormatError


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass
class PEFile:
    path: str
    data: bytes
    machine: int
    sections: list[Section] = field(default_factory=list)
    is_64: bool = False
    entry_point: int = 0
    image_base: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    import_rva: int = 0
    import_size: int = 0


MACHINE_NAMES = {
    332: "x86",
    34404: "x64",
    452: "ARM",
    43620: "ARM64",
}


SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "RegOpenKeyA",
    "RegOpenKeyW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "WinHttpOpen",
}


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def c_string(data, offset, limit=4096):
    if offset is None or offset < 0 or offset >= len(data):
        return ""

    end = data.find(
        b"\x00",
        offset,
        min(len(data), offset + limit),
    )

    if end < 0:
        end = min(len(data), offset + limit)

    return data[offset:end].decode("ascii", errors="replace")


def parse(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise PEFormatError(f"Cannot read file: {e}") from e

    if len(data) < 64 or data[:2] != b"MZ":
        raise PEFormatError("Not a valid PE file: missing MZ signature.")

    pe_offset = u32(data, 60)

    if pe_offset + 24 > len(data):
        raise PEFormatError("Invalid PE header offset.")

    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise PEFormatError("Not a valid PE file: missing PE signature.")

    fh = pe_offset + 4
    machine, sections_count, _, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH",
        data,
        fh,
    )
    optional = fh + 20

    if optional + optional_size > len(data):
        raise PEFormatError("Truncated optional header.")

    magic = u16(data, optional)

    if magic == 523:
        (
            is64,
            entry,
            image,
            sec_align,
            file_align,
            dir_off,
        ) = (
            True,
            u32(data, optional + 16),
            u64(data, optional + 24),
            u32(data, optional + 32),
            u32(data, optional + 36),
            optional + 112,
        )
    elif magic == 267:
        (
            is64,
            entry,
            image,
            sec_align,
            file_align,
            dir_off,
        ) = (
            False,
            u32(data, optional + 16),
            u32(data, optional + 28),
            u32(data, optional + 32),
            u32(data, optional + 36),
            optional + 96,
        )
    else:
        raise PEFormatError(
            f"Unsupported Optional Header magic: 0x{magic:04x}"
        )

    dirs = (
        u32(data, dir_off)
        if dir_off + 4 <= optional + optional_size
        else 0
    )
    imp_rva = imp_size = 0

    if dirs > 1 and dir_off + 16 <= optional + optional_size:
        imp_rva, imp_size = (
            u32(data, dir_off + 8),
            u32(data, dir_off + 12),
        )

    table = optional + optional_size
    sections = []

    for i in range(sections_count):
        off = table + i * 40

        if off + 40 > len(data):
            raise PEFormatError("Truncated section table.")

        name = (
            data[off : off + 8]
            .split(b"\x00", 1)[0]
            .decode("ascii", errors="replace")
        )

        sections.append(
            Section(
                name,
                u32(data, off + 8),
                u32(data, off + 12),
                u32(data, off + 16),
                u32(data, off + 20),
                u32(data, off + 36),
            )
        )

    return PEFile(
        path,
        data,
        machine,
        sections,
        is64,
        entry,
        image,
        sec_align,
        file_align,
        imp_rva,
        imp_size,
    )


def rva_to_offset(pe, rva):
    for s in pe.sections:
        size = max(s.virtual_size, s.raw_size)

        if s.virtual_address <= rva < s.virtual_address + size:
            delta = rva - s.virtual_address

            if delta < s.raw_size:
                return s.raw_offset + delta

    return None


def section_data(pe, section):
    if section.raw_offset >= len(pe.data):
        return b""

    return pe.data[
        section.raw_offset : min(
            len(pe.data),
            section.raw_offset + section.raw_size,
        )
    ]


def ascii_strings(data, minimum=5):
    result, current, start = ([], bytearray(), 0)

    for i, byte in enumerate(data):
        if 32 <= byte <= 126:
            if not current:
                start = i
            current.append(byte)
        else:
            if len(current) >= minimum:
                result.append((start, current.decode("ascii")))
            current.clear()

    if len(current) >= minimum:
        result.append((start, current.decode("ascii")))

    return result


def entropy(data):
    if not data:
        return 0.0

    counts, total = (Counter(data), len(data))
    return -sum(
        (n / total * math.log2(n / total) for n in counts.values())
    )


def imports(pe):
    if not pe.import_rva:
        return []

    base = rva_to_offset(pe, pe.import_rva)

    if base is None:
        return []

    result = []

    for i in range(10000):
        off = base + i * 20

        if off + 20 > len(pe.data):
            break

        oft, name_rva, ft = (
            u32(pe.data, off),
            u32(pe.data, off + 12),
            u32(pe.data, off + 16),
        )

        if oft == 0 and name_rva == 0 and ft == 0:
            break

        noff = rva_to_offset(pe, name_rva)
        dll = c_string(pe.data, noff) if noff is not None else "<?>"
        thunk = rva_to_offset(pe, oft or ft)
        apis, step = ([], 8 if pe.is_64 else 4)

        if thunk is not None:
            for j in range(10000):
                pos = thunk + j * step

                if pos + step > len(pe.data):
                    break

                value = u64(pe.data, pos) if pe.is_64 else u32(pe.data, pos)

                if value == 0:
                    break

                flag = 1 << (63 if pe.is_64 else 31)

                if value & flag:
                    apis.append(f"Ordinal_{value & 65535}")
                else:
                    hn = rva_to_offset(
                        pe,
                        value
                        & (
                            9223372036854775807
                            if pe.is_64
                            else 2147483647
                        ),
                    )

                    if hn is not None:
                        apis.append(c_string(pe.data, hn + 2, 1024))

        result.append((dll, apis))

    return result


def security_indicators(pe, imported, threshold=7.2):
    apis = {api for _, items in imported for api in items}
    api_hits = sorted(apis & SUSPICIOUS_APIS)
    entropy_hits = [
        s.name
        for s in pe.sections
        if len(section_data(pe, s)) >= 256
        and entropy(section_data(pe, s)) >= threshold
    ]

    return (api_hits, entropy_hits)
