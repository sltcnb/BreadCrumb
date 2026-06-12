"""BitLocker (FVE) volume unlock + transparent decryption.

Turns a locked Windows volume into a plaintext one in place: given a credential
(recovery password, passphrase, startup .BEK key, raw FVEK, or a suspended
volume's clear key) it parses the FVE metadata, recovers the Volume Master Key
then the Full Volume Encryption Key, and decrypts sectors on demand.

Supported data ciphers:
    AES-XTS-128 / AES-XTS-256            (Windows 8+/10/11 default, incl. SSDs)
    AES-CBC-128 / AES-CBC-256           (no diffuser)
    AES-CBC-128/256 + Elephant diffuser  (Vista / 7 default)

The decryption engine is pure-Python and self-contained; if the `cryptography`
package is installed its C-backed AES is used transparently for a large speedup
(see _aes.py). Everything is read-only — no plaintext is ever written back to
the source.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field

from . import _aes

# -- FVE constants ---------------------------------------------------------

FVE_SIGNATURE = b"-FVE-FS-"

# data encryption methods (FVE metadata header, encryption_method field)
M_STRETCH_NONE = 0x0000
M_AES_CBC_128_DIFFUSER = 0x8000
M_AES_CBC_256_DIFFUSER = 0x8001
M_AES_CBC_128 = 0x8002
M_AES_CBC_256 = 0x8003
M_AES_XTS_128 = 0x8004
M_AES_XTS_256 = 0x8005

_METHOD_NAMES = {
    M_AES_CBC_128_DIFFUSER: "AES-CBC-128 + diffuser",
    M_AES_CBC_256_DIFFUSER: "AES-CBC-256 + diffuser",
    M_AES_CBC_128: "AES-CBC-128",
    M_AES_CBC_256: "AES-CBC-256",
    M_AES_XTS_128: "AES-XTS-128",
    M_AES_XTS_256: "AES-XTS-256",
}

# metadata entry value types
VT_ERASED = 0x0000
VT_KEY = 0x0001
VT_UNICODE = 0x0002
VT_STRETCH_KEY = 0x0003
VT_USE_KEY = 0x0004
VT_AES_CCM_KEY = 0x0005
VT_TPM_KEY = 0x0006
VT_VALIDATION = 0x0007
VT_VMK = 0x0008
VT_EXTERNAL_KEY = 0x0009

# metadata entry types
ET_VMK = 0x0002
ET_FVEK = 0x0003

# VMK protection types (high byte of protection_type word)
PROT_CLEAR = 0x0000
PROT_TPM = 0x0100
PROT_STARTUP_KEY = 0x0200
PROT_TPM_PIN = 0x0500
PROT_RECOVERY = 0x0800
PROT_PASSWORD = 0x2000

STRETCH_COUNT = 0x100000          # SHA-256 iterations; module-level for tests


class BitLockerError(Exception):
    pass


# -- credentials -----------------------------------------------------------

@dataclass
class Credentials:
    recovery: str | None = None       # 48-digit recovery password
    password: str | None = None       # user passphrase
    bek: bytes | None = None          # external startup key (.BEK contents)
    fvek: bytes | None = None         # raw FVEK bytes (skip key recovery)

    @classmethod
    def from_env(cls) -> "Credentials | None":
        raw = os.environ.get("CARVX_BITLOCKER")
        if not raw:
            return None
        import json
        d = json.loads(raw)
        bek = bytes.fromhex(d["bek"]) if d.get("bek") else None
        fvek = bytes.fromhex(d["fvek"]) if d.get("fvek") else None
        return cls(recovery=d.get("recovery"), password=d.get("password"),
                   bek=bek, fvek=fvek)

    def to_env(self) -> str:
        import json
        d = {}
        if self.recovery:
            d["recovery"] = self.recovery
        if self.password:
            d["password"] = self.password
        if self.bek:
            d["bek"] = self.bek.hex()
        if self.fvek:
            d["fvek"] = self.fvek.hex()
        return json.dumps(d)


# -- key derivation --------------------------------------------------------

def parse_recovery_password(text: str) -> bytes:
    """48 decimal digits (optionally dash-grouped 6x8) -> 16-byte intermediate."""
    groups = [g for g in text.replace(" ", "").split("-") if g]
    if len(groups) == 1 and len(groups[0]) == 48:
        s = groups[0]
        groups = [s[i:i + 6] for i in range(0, 48, 6)]
    if len(groups) != 8 or any(len(g) != 6 or not g.isdigit() for g in groups):
        raise BitLockerError("recovery password must be 8 groups of 6 digits")
    out = bytearray()
    for g in groups:
        v = int(g)
        if v % 11 != 0:
            raise BitLockerError(f"recovery group {g} not divisible by 11")
        v //= 11
        if v > 0xFFFF:
            raise BitLockerError(f"recovery group {g} out of range")
        out += struct.pack("<H", v)
    return bytes(out)


def _password_hash(data: bytes) -> bytes:
    """SHA-256 applied twice — the BitLocker user/recovery key hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def stretch_key(password_hash: bytes, salt: bytes) -> bytes:
    """BitLocker key-stretch: STRETCH_COUNT SHA-256 rounds over an 88-byte struct
    (last_hash[32] || initial_hash[32] || salt[16] || count_u64)."""
    last = bytearray(32)
    initial = password_hash
    count = 0
    pack = struct.Struct("<Q").pack
    sha = hashlib.sha256
    for _ in range(STRETCH_COUNT):
        last = bytearray(sha(bytes(last) + initial + salt + pack(count)).digest())
        count += 1
    return bytes(last)


# -- metadata parsing ------------------------------------------------------

@dataclass
class _Entry:
    etype: int
    vtype: int
    version: int
    data: bytes


def _walk_entries(blob: bytes):
    """Yield FVE metadata entries from a blob (header: size,type,vtype,version)."""
    off = 0
    n = len(blob)
    while off + 8 <= n:
        size, etype, vtype, version = struct.unpack_from("<HHHH", blob, off)
        if size < 8 or off + size > n:
            break
        yield _Entry(etype, vtype, version, blob[off + 8:off + size])
        off += size


@dataclass
class FveMetadata:
    encryption_method: int
    volume_identifier: bytes
    header_sectors: int               # original boot sectors relocated by BDE
    volume_header_offset: int         # where their decrypted backup lives
    encrypted_volume_size: int
    entries: list = field(default_factory=list)


def parse_metadata(block: bytes) -> FveMetadata:
    """Parse one FVE metadata block (starting at its 64-byte block header)."""
    if block[:8] != FVE_SIGNATURE:
        raise BitLockerError("FVE metadata signature missing")
    # block header (0x40): grab the relocated-volume-header location.
    encrypted_volume_size = struct.unpack_from("<Q", block, 0x10)[0]
    header_sectors = struct.unpack_from("<I", block, 0x1C)[0]
    volume_header_offset = struct.unpack_from("<Q", block, 0x20)[0]
    # FVE metadata header (0x30) follows the block header.
    mh = block[0x40:0x70]
    metadata_size = struct.unpack_from("<I", mh, 0)[0]
    volume_identifier = mh[0x10:0x20]
    encryption_method = struct.unpack_from("<I", mh, 0x24)[0] & 0xFFFF
    body = block[0x70:0x40 + metadata_size]
    entries = list(_walk_entries(body))
    return FveMetadata(encryption_method, volume_identifier, header_sectors,
                       volume_header_offset, encrypted_volume_size, entries)


def _ccm_blob_decrypt(key: bytes, blob: bytes) -> bytes:
    """AES-CCM key entry data = nonce(12) || MAC(16) || ciphertext -> plaintext."""
    nonce = blob[:12]
    return _aes.ccm_decrypt(key, nonce, blob[12:])


def _key_from_payload(payload: bytes) -> bytes:
    """A decrypted CCM 'key' payload is a 4-byte header then the raw key bytes."""
    return payload[4:]


# -- VMK / FVEK recovery ---------------------------------------------------

def _unlock_vmk(vmk_entry: _Entry, creds: Credentials) -> bytes | None:
    """Try to turn one VMK metadata entry into the plaintext VMK."""
    data = vmk_entry.data
    protection = struct.unpack_from("<H", data, 0x1A)[0]
    nested = list(_walk_entries(data[0x1C:]))

    def find(vt):
        return next((e for e in nested if e.vtype == vt), None)

    # Clear key (suspended BitLocker): the VMK sits in the open.
    if protection == PROT_CLEAR:
        k = find(VT_KEY)
        if k:
            return _key_from_payload(k.data)

    stretch = find(VT_STRETCH_KEY)
    ccm = find(VT_AES_CCM_KEY)

    # Recovery password / passphrase: stretch a salt, AES-CCM-unwrap the VMK.
    if stretch and ccm:
        salt = stretch.data[4:20]
        secret = None
        if creds.recovery and (protection == PROT_RECOVERY or protection == 0):
            secret = parse_recovery_password(creds.recovery)
        elif creds.password and protection in (PROT_PASSWORD, PROT_TPM_PIN):
            secret = creds.password.encode("utf-16-le")
        if secret is not None:
            dk = stretch_key(_password_hash(secret), salt)
            try:
                payload = _ccm_blob_decrypt(dk, ccm.data)
                return _key_from_payload(payload)
            except ValueError:
                return None

    # Startup key (.BEK): the external key AES-CCM-unwraps the VMK directly.
    if creds.bek and ccm and protection == PROT_STARTUP_KEY:
        ext = _external_key_from_bek(creds.bek)
        if ext is not None:
            try:
                return _key_from_payload(_ccm_blob_decrypt(ext, ccm.data))
            except ValueError:
                return None
    return None


def _external_key_from_bek(bek: bytes) -> bytes | None:
    """A .BEK file is an FVE metadata block whose external-key entry holds a raw
    key; return that key."""
    try:
        meta = parse_metadata(bek)
    except BitLockerError:
        return None
    for e in meta.entries:
        if e.vtype == VT_EXTERNAL_KEY:
            for n in _walk_entries(e.data[0x1C:]):
                if n.vtype == VT_KEY:
                    return _key_from_payload(n.data)
        if e.vtype == VT_KEY:
            return _key_from_payload(e.data)
    return None


def recover_fvek(meta: FveMetadata, creds: Credentials) -> bytes:
    """Recover the FVEK key material from metadata + credentials."""
    if creds.fvek:
        return creds.fvek
    vmk = None
    for e in meta.entries:
        if e.vtype == VT_VMK:
            vmk = _unlock_vmk(e, creds)
            if vmk:
                break
    if not vmk:
        raise BitLockerError(
            "no VMK could be unlocked with the supplied credential "
            "(wrong recovery key / password, or unsupported protector)")
    # FVEK entry: AES-CCM key wrapped under the VMK.
    fvek_entry = next((e for e in meta.entries
                       if e.etype == ET_FVEK and e.vtype == VT_AES_CCM_KEY), None)
    if fvek_entry is None:
        fvek_entry = next((e for e in meta.entries
                           if e.vtype == VT_AES_CCM_KEY), None)
    if fvek_entry is None:
        raise BitLockerError("no FVEK entry in metadata")
    payload = _ccm_blob_decrypt(vmk, fvek_entry.data)
    return _key_from_payload(payload)


# -- volume cipher ---------------------------------------------------------

class _Cipher:
    """Sector-level decrypt for one FVE encryption method."""

    def __init__(self, method: int, fvek: bytes, sector_size: int):
        self.method = method
        self.sector_size = sector_size
        self.diffuser = method in (M_AES_CBC_128_DIFFUSER, M_AES_CBC_256_DIFFUSER)
        self.xts = method in (M_AES_XTS_128, M_AES_XTS_256)
        half = {
            M_AES_XTS_128: 16, M_AES_XTS_256: 32,
            M_AES_CBC_128_DIFFUSER: 16, M_AES_CBC_256_DIFFUSER: 32,
        }.get(method)
        if self.xts:
            self.aes1 = _aes.AES(fvek[:half])
            self.aes2 = _aes.AES(fvek[half:half * 2])
        elif self.diffuser:
            self.aes1 = _aes.AES(fvek[:half])           # CBC key
            self.aes2 = _aes.AES(fvek[half:half * 2])   # tweak/sector key
        elif method == M_AES_CBC_128:
            self.aes1 = _aes.AES(fvek[:16])
        elif method == M_AES_CBC_256:
            self.aes1 = _aes.AES(fvek[:32])
        else:
            raise BitLockerError(f"unsupported encryption method {method:#06x}")

    def decrypt_sector(self, sector_no: int, data: bytes) -> bytes:
        if self.xts:
            return _aes.xts_decrypt(self.aes1, self.aes2, sector_no, data)
        iv = self.aes1.encrypt(struct.pack("<Q", sector_no) + b"\x00" * 8)
        if not self.diffuser:
            return _aes.cbc_decrypt(self.aes1, iv, data)
        # CBC + Elephant diffuser: CBC-decrypt, then undo diffuser with Ks.
        plain = _aes.cbc_decrypt(self.aes1, iv, data)
        sk = self._sector_key(sector_no, len(data))
        return _aes.diffuser_decrypt(plain, sk)

    def _encrypt_sector(self, sector_no: int, data: bytes) -> bytes:
        """Inverse of decrypt_sector. Used only by the test builder."""
        if self.xts:
            return _aes.xts_encrypt(self.aes1, self.aes2, sector_no, data)
        iv = self.aes1.encrypt(struct.pack("<Q", sector_no) + b"\x00" * 8)
        if not self.diffuser:
            return _aes.cbc_encrypt(self.aes1, iv, data)
        sk = self._sector_key(sector_no, len(data))
        diffused = _aes.diffuser_encrypt(data, sk)
        return _aes.cbc_encrypt(self.aes1, iv, diffused)

    def _sector_key(self, sector_no: int, size: int) -> bytes:
        b = bytearray(struct.pack("<Q", sector_no) + b"\x00" * 8)
        k = bytearray(self.aes2.encrypt(bytes(b)))
        b[15] = 0x80
        k += self.aes2.encrypt(bytes(b))
        return (bytes(k) * (size // len(k) + 1))[:size]


# -- unlocked volume -------------------------------------------------------

class BitLockerVolume:
    """An unlocked FVE volume. Decrypts on demand; presents plaintext sectors."""

    def __init__(self, reader, base: int, meta: FveMetadata, fvek: bytes,
                 sector_size: int, volume_size: int):
        self.reader = reader
        self.base = base
        self.meta = meta
        self.sector_size = sector_size
        self.size = volume_size
        self.cipher = _Cipher(meta.encryption_method, fvek, sector_size)
        self.method_name = _METHOD_NAMES.get(meta.encryption_method, "?")
        # The first header_sectors at the volume start are BDE boot code; the
        # real (encrypted) originals are backed up at volume_header_offset.
        self._hdr_bytes = meta.header_sectors * sector_size
        self._hdr_src = meta.volume_header_offset

    def read(self, offset: int, length: int) -> bytes:
        """Plaintext bytes at a volume-relative offset (sector aligned I/O)."""
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        ss = self.sector_size
        start = offset - offset % ss
        end = offset + length
        end += -end % ss
        out = bytearray()
        pos = start
        while pos < end:
            out += self._decrypt_one(pos)
            pos += ss
        return bytes(out[offset - start:offset - start + length])

    def _decrypt_one(self, vpos: int) -> bytes:
        """Decrypt the single sector at volume offset vpos (sector aligned)."""
        ss = self.sector_size
        sector_no = vpos // ss
        if vpos < self._hdr_bytes and self._hdr_src:
            # served from the relocated, still-encrypted header backup
            src = self._hdr_src + vpos
            ct = self.reader.pread(src, ss)
            return self.cipher.decrypt_sector(src // ss, ct)
        ct = self.reader.pread(self.base + vpos, ss)
        if len(ct) < ss:
            ct = ct + b"\x00" * (ss - len(ct))
        return self.cipher.decrypt_sector(sector_no, ct)


# -- detection + unlock ----------------------------------------------------

def _metadata_offsets(boot: bytes) -> list[int]:
    """Three FVE metadata block offsets stored at 0x160 of the boot sector."""
    if len(boot) < 0x178:
        return []
    return [struct.unpack_from("<Q", boot, 0x160 + i * 8)[0] for i in range(3)]


def is_bitlocker(reader, base: int) -> bool:
    boot = reader.pread(base, 512)
    return len(boot) >= 11 and boot[3:11] == FVE_SIGNATURE


def unlock_volume(reader, base: int, creds: Credentials,
                  log=None) -> BitLockerVolume | None:
    """Detect + unlock a BitLocker volume at `base`. Returns None if not FVE."""
    boot = reader.pread(base, 512)
    if len(boot) < 11 or boot[3:11] != FVE_SIGNATURE:
        return None
    sector_size = struct.unpack_from("<H", boot, 11)[0] or 512
    meta = None
    for off in _metadata_offsets(boot):
        if off == 0:
            continue
        block = reader.pread(base + off, 0x10000)
        if block[:8] == FVE_SIGNATURE:
            try:
                meta = parse_metadata(block)
                break
            except BitLockerError:
                continue
    if meta is None:
        raise BitLockerError("FVE boot sector found but no valid metadata block")
    fvek = recover_fvek(meta, creds)
    vol_size = meta.encrypted_volume_size or (reader.size - base)
    vol = BitLockerVolume(reader, base, meta, fvek, sector_size, vol_size)
    if log:
        log(f"bitlocker: unlocked volume @ {base:#x} ({vol.method_name}, "
            f"{vol_size / (1 << 30):.1f} GiB)")
    return vol
