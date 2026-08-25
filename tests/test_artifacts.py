"""Deletion-time artefacts: recycle-bin $I records and the NTFS change journal.

The structures are built here from their documented field layouts, and the
timestamps are checked against dates worked out independently, so the tests do
not simply agree with the parser.
"""

import datetime
import struct

from breadcrumb import artifacts


def _filetime(iso: str) -> int:
    """FILETIME for an ISO-8601 UTC instant, computed independently of the
    parser: seconds since 1601-01-01 in 100 ns units."""
    dt = datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.timezone.utc)
    epoch_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return int((dt - epoch_1601).total_seconds()) * 10_000_000


def _utc(unix: int) -> str:
    return datetime.datetime.fromtimestamp(
        unix, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------- $I records

def _recycle_v1(path: str, size: int, when: str) -> bytes:
    body = struct.pack("<QQQ", 1, size, _filetime(when))
    raw = path.encode("utf-16-le")
    return body + raw + b"\x00" * (520 - len(raw))


def _recycle_v2(path: str, size: int, when: str) -> bytes:
    raw = path.encode("utf-16-le") + b"\x00\x00"
    return (struct.pack("<QQQ", 2, size, _filetime(when))
            + struct.pack("<I", len(raw) // 2) + raw)


def test_recycle_v1_and_v2_agree_on_the_same_deletion():
    path = r"C:\Users\jl\Documents\payroll.xlsx"
    for build in (_recycle_v1, _recycle_v2):
        entry = artifacts.parse_recycle_i(build(path, 44_321, "2026-08-24T15:14:05"))
        assert entry is not None
        assert entry.path == path
        assert entry.size == 44_321
        assert _utc(entry.deleted) == "2026-08-24 15:14:05"


def test_recycle_rejects_unknown_versions_and_truncation():
    good = _recycle_v2(r"C:\x.txt", 1, "2026-01-01T00:00:00")
    assert artifacts.parse_recycle_i(good) is not None
    bad_version = bytearray(good)
    struct.pack_into("<Q", bad_version, 0, 7)
    assert artifacts.parse_recycle_i(bytes(bad_version)) is None
    assert artifacts.parse_recycle_i(good[:20]) is None
    # a v2 record whose declared path runs past the end
    short = bytearray(good)
    struct.pack_into("<I", short, 24, 4096)
    assert artifacts.parse_recycle_i(bytes(short)) is None


# ---------------------------------------------------------- USN journal

def _usn_v2(name: str, reason: int, when: str, usn: int = 0x1000,
            file_ref: int = 0x0002_0000_0000_002A, parent: int = 5) -> bytes:
    raw = name.encode("utf-16-le")
    head = 60
    length = head + len(raw)
    length += (-length) % 8                       # records are 8-byte aligned
    rec = bytearray(length)
    struct.pack_into("<IHH", rec, 0, length, 2, 0)
    struct.pack_into("<QQ", rec, 8, file_ref, parent)
    struct.pack_into("<Q", rec, 24, usn)
    struct.pack_into("<Q", rec, 32, _filetime(when))
    struct.pack_into("<II", rec, 40, reason, 0)   # reason, source info
    struct.pack_into("<II", rec, 48, 0, 0x20)     # security id, attributes
    struct.pack_into("<HH", rec, 56, len(raw), head)
    rec[head:head + len(raw)] = raw
    return bytes(rec)


def _usn_v3(name: str, reason: int, when: str) -> bytes:
    raw = name.encode("utf-16-le")
    head = 76
    length = head + len(raw)
    length += (-length) % 8
    rec = bytearray(length)
    struct.pack_into("<IHH", rec, 0, length, 3, 0)
    rec[8:24] = bytes(range(16))                  # 128-bit file reference
    rec[24:40] = bytes(range(16, 32))             # 128-bit parent reference
    struct.pack_into("<Q", rec, 40, 0x2000)
    struct.pack_into("<Q", rec, 48, _filetime(when))
    struct.pack_into("<II", rec, 56, reason, 0)
    struct.pack_into("<II", rec, 64, 0, 0x20)
    struct.pack_into("<HH", rec, 72, len(raw), head)
    rec[head:head + len(raw)] = raw
    return bytes(rec)


def test_usn_records_parse_with_reasons_and_times():
    data = (_usn_v2("report.docx", artifacts.USN_REASON_FILE_DELETE | 0x80000000,
                    "2026-08-20T09:30:00")
            + _usn_v2("kept.txt", 0x00000001, "2026-08-20T09:31:00")
            + _usn_v3("photo.jpg", artifacts.USN_REASON_FILE_DELETE,
                      "2026-08-21T18:00:00"))
    records = list(artifacts.parse_usn_journal(data))
    assert [r.name for r in records] == ["report.docx", "kept.txt", "photo.jpg"]
    assert [r.deleted for r in records] == [True, False, True]
    assert _utc(records[0].timestamp) == "2026-08-20 09:30:00"
    assert records[0].mft_record == 0x2A
    assert "file-delete" in artifacts.describe_reasons(records[0].reason)
    assert "close" in artifacts.describe_reasons(records[0].reason)
    assert records[2].version == (3, 0)


def test_usn_skips_sparse_holes_and_resynchronises():
    """A $J stream starts with a hole, and a carved copy can begin mid-record."""
    good = _usn_v2("late.docx", artifacts.USN_REASON_FILE_DELETE,
                   "2026-08-22T12:00:00")
    data = bytes(4096) + b"\x11" * 32 + good      # hole, then junk, then a record
    names = [r.name for r in artifacts.parse_usn_journal(data)]
    assert names == ["late.docx"]


def test_usn_rejects_absurd_record_lengths():
    bad = bytearray(_usn_v2("x.txt", 0x200, "2026-01-01T00:00:00"))
    struct.pack_into("<I", bad, 0, 1 << 20)       # length beyond the buffer
    assert list(artifacts.parse_usn_journal(bytes(bad))) == []


# ------------------------------------------------------------- reporting

def test_events_csv_is_sorted_and_dated(tmp_path):
    data = (_usn_v2("second.docx", artifacts.USN_REASON_FILE_DELETE,
                    "2026-08-24T10:00:00")
            + _usn_v2("first.docx", artifacts.USN_REASON_FILE_DELETE,
                      "2026-08-23T10:00:00"))
    events = artifacts.events_from_usn(data)
    events += artifacts.events_from_recycle(
        _recycle_v2(r"C:\tmp\third.pdf", 10, "2026-08-25T10:00:00"))
    out = tmp_path / "deleted.csv"
    assert artifacts.write_events_csv(events, str(out)) == 3
    rows = out.read_text().splitlines()
    assert rows[0] == "deleted_utc,unix,source,name,size,detail"
    assert "first.docx" in rows[1] and "2026-08-23" in rows[1]
    assert "third.pdf" in rows[3] and "$I" in rows[3]


def test_scan_tree_finds_artefacts_by_name(tmp_path):
    """An --ntfs run recovers these as ordinary files, names intact."""
    (tmp_path / "$Recycle.Bin").mkdir()
    (tmp_path / "$Recycle.Bin" / "$IABCDEF.xlsx").write_bytes(
        _recycle_v2(r"D:\finance\q3.xlsx", 999, "2026-07-01T08:00:00"))
    (tmp_path / "$Extend").mkdir()
    (tmp_path / "$Extend" / "$UsnJrnl-$J").write_bytes(
        _usn_v2("gone.docx", artifacts.USN_REASON_FILE_DELETE,
                "2026-07-02T09:00:00"))
    events = artifacts.scan_tree_for_artefacts(str(tmp_path))
    names = sorted(e.name for e in events)
    assert names == ["D:\\finance\\q3.xlsx", "gone.docx"]
    assert {e.source for e in events} == {"$I", "$UsnJrnl"}


def test_filetime_conversion_matches_a_known_instant():
    # 1601-01-01 is FILETIME 0; the Unix epoch is 11644473600 seconds later.
    assert artifacts._ft2unix(0) == 0
    assert artifacts._ft2unix(11_644_473_600 * 10_000_000) == 0
    assert _utc(artifacts._ft2unix(_filetime("2026-08-25T12:00:00"))) == \
        "2026-08-25 12:00:00"
