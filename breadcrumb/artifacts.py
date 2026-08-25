"""Windows artefacts that record when a file was deleted.

NTFS itself has no deletion timestamp: `$STANDARD_INFORMATION` carries created,
modified, changed and accessed, and the record's change time is only a proxy for
when it went away. Two artefacts do record deletion directly:

    $Recycle.Bin/$I*   one per Explorer-deleted file: deletion time, original
                       size, and the full original path
    $Extend/$UsnJrnl:$J  the change journal, with an explicit FILE_DELETE
                       reason per record and a timestamp

Both are parsed here so a timeline can say when something was deleted rather
than inferring it.
"""

import struct
from dataclasses import dataclass, field

# USN change reasons (winioctl.h). Only the ones a timeline cares about are
# named; the rest are reported as their hex value.
USN_REASONS = [
    (0x00000001, "data-overwrite"), (0x00000002, "data-extend"),
    (0x00000004, "data-truncation"), (0x00000010, "named-data-overwrite"),
    (0x00000020, "named-data-extend"), (0x00000040, "named-data-truncation"),
    (0x00000100, "file-create"), (0x00000200, "file-delete"),
    (0x00000400, "ea-change"), (0x00000800, "security-change"),
    (0x00001000, "rename-old-name"), (0x00002000, "rename-new-name"),
    (0x00004000, "indexable-change"), (0x00008000, "basic-info-change"),
    (0x00010000, "hard-link-change"), (0x00020000, "compression-change"),
    (0x00040000, "encryption-change"), (0x00080000, "object-id-change"),
    (0x00100000, "reparse-point-change"), (0x00200000, "stream-change"),
    (0x00400000, "transacted-change"), (0x00800000, "integrity-change"),
    (0x80000000, "close"),
]

USN_REASON_FILE_DELETE = 0x00000200


def _ft2unix(ft: int) -> int:
    """Windows FILETIME (100 ns since 1601) to a Unix timestamp."""
    if ft <= 0:
        return 0
    return max(0, ft // 10_000_000 - 11_644_473_600)


def describe_reasons(reason: int) -> str:
    """Reason bitmask as a readable, stable string."""
    names = [n for bit, n in USN_REASONS if reason & bit]
    left = reason & ~sum(bit for bit, _ in USN_REASONS)
    if left:
        names.append(f"{left:#010x}")
    return "|".join(names) if names else "none"


# ------------------------------------------------------- $Recycle.Bin/$I

@dataclass
class RecycleEntry:
    deleted: int             # unix seconds
    size: int               # original file size in bytes
    path: str               # original full path
    version: int


def parse_recycle_i(data: bytes) -> RecycleEntry | None:
    """Parse one `$I` record from the recycle bin.

    Version 1 (Vista..8.1) stores the original path as a fixed 260-character
    field; version 2 (Windows 10+) precedes it with a character count. Anything
    else, or a record whose path runs past the end, is rejected rather than
    guessed at.
    """
    if len(data) < 24:
        return None
    version = struct.unpack_from("<Q", data, 0)[0]
    size = struct.unpack_from("<Q", data, 8)[0]
    deleted = _ft2unix(struct.unpack_from("<Q", data, 16)[0])
    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2:
        if len(data) < 28:
            return None
        chars = struct.unpack_from("<I", data, 24)[0]
        if not (1 <= chars <= 32768):
            return None
        raw = data[28:28 + chars * 2]
        if len(raw) < chars * 2:
            return None
    else:
        return None
    path = raw.decode("utf-16-le", "replace").split("\x00", 1)[0]
    if not path:
        return None
    return RecycleEntry(deleted=deleted, size=size, path=path, version=version)


# --------------------------------------------------- $Extend/$UsnJrnl:$J

@dataclass
class UsnRecord:
    usn: int
    timestamp: int          # unix seconds
    reason: int
    name: str
    file_ref: int           # MFT reference number (low 48 bits are the record)
    parent_ref: int
    version: tuple = field(default_factory=tuple)

    @property
    def mft_record(self) -> int:
        return self.file_ref & 0x0000_FFFF_FFFF_FFFF

    @property
    def deleted(self) -> bool:
        return bool(self.reason & USN_REASON_FILE_DELETE)


def parse_usn_journal(data: bytes, start: int = 0):
    """Yield USN records from a `$J` stream.

    The journal is a sparse file that usually starts with a large hole, and a
    carved copy can begin mid-record, so this skips zero runs and resynchronises
    on the next plausible record rather than giving up at the first bad length.
    V2 records carry 64-bit file references, V3 128-bit ones.
    """
    pos = start
    end = len(data)
    while pos + 60 <= end:
        length = struct.unpack_from("<I", data, pos)[0]
        if length == 0:
            pos += 8                      # sparse hole: step over it
            continue
        if length < 56 or length > 1024 or pos + length > end:
            pos += 8                      # not a record boundary: resynchronise
            continue
        major = struct.unpack_from("<H", data, pos + 4)[0]
        minor = struct.unpack_from("<H", data, pos + 6)[0]
        if major == 2:
            file_ref = struct.unpack_from("<Q", data, pos + 8)[0]
            parent_ref = struct.unpack_from("<Q", data, pos + 16)[0]
            head = 24
        elif major == 3:
            file_ref = struct.unpack_from("<Q", data, pos + 8)[0]
            parent_ref = struct.unpack_from("<Q", data, pos + 24)[0]
            head = 40
        else:
            pos += 8
            continue
        usn = struct.unpack_from("<Q", data, pos + head)[0]
        timestamp = _ft2unix(struct.unpack_from("<Q", data, pos + head + 8)[0])
        reason = struct.unpack_from("<I", data, pos + head + 16)[0]
        # From the Usn field: timestamp +8, reason +16, source info +20,
        # security id +24, attributes +28, name length +32, name offset +34.
        name_len = struct.unpack_from("<H", data, pos + head + 32)[0]
        name_off = struct.unpack_from("<H", data, pos + head + 34)[0]
        if name_off + name_len > length or name_len == 0:
            pos += length
            continue
        name = data[pos + name_off:pos + name_off + name_len].decode(
            "utf-16-le", "replace")
        yield UsnRecord(usn=usn, timestamp=timestamp, reason=reason, name=name,
                        file_ref=file_ref, parent_ref=parent_ref,
                        version=(major, minor))
        pos += length


# ------------------------------------------------------------- reporting

@dataclass
class DeletionEvent:
    when: int               # unix seconds
    source: str             # "$I" | "$UsnJrnl"
    name: str               # file name, or the original full path for $I
    size: int = 0
    detail: str = ""        # reason flags, or the $I version


def events_from_recycle(data: bytes, label: str = "") -> list:
    entry = parse_recycle_i(data)
    if entry is None:
        return []
    return [DeletionEvent(when=entry.deleted, source="$I", name=entry.path,
                          size=entry.size,
                          detail=f"v{entry.version}{' ' + label if label else ''}")]


def events_from_usn(data: bytes, deletions_only: bool = True) -> list:
    out = []
    for rec in parse_usn_journal(data):
        if deletions_only and not rec.deleted:
            continue
        out.append(DeletionEvent(
            when=rec.timestamp, source="$UsnJrnl", name=rec.name,
            detail=f"mft {rec.mft_record} {describe_reasons(rec.reason)}"))
    return out


def write_events_csv(events: list, path: str) -> int:
    """Write deletion events sorted oldest first. Returns the row count."""
    import csv
    import datetime
    rows = sorted(events, key=lambda e: (e.when, e.name))
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["deleted_utc", "unix", "source", "name", "size", "detail"])
        for e in rows:
            iso = ""
            if e.when:
                iso = datetime.datetime.fromtimestamp(
                    e.when, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            w.writerow([iso, e.when, e.source, e.name, e.size, e.detail])
    return len(rows)


def scan_tree_for_artefacts(root: str) -> list:
    """Find recycle-bin $I records and $UsnJrnl streams under a directory.

    Point this at an --ntfs output tree: the artefacts come back as recovered
    files, and their names are preserved, so they can be found and parsed.
    """
    import os
    events = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            low = name.lower()
            try:
                if low.startswith("$i") and len(name) > 2:
                    with open(full, "rb") as fh:
                        events += events_from_recycle(fh.read(4096), name)
                elif "usnjrnl" in low:
                    with open(full, "rb") as fh:
                        events += events_from_usn(fh.read())
            except OSError:
                continue
    return events
