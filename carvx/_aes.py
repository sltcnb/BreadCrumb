"""AES primitives for BitLocker: ECB block, CBC, XTS, CCM, Elephant diffuser.

Zero-dependency by default: a compact pure-Python AES is built in. If the
`cryptography` package is importable it is used transparently for the per-block
AES (orders of magnitude faster), while the XTS/CBC/CCM/diffuser composition
stays here so behaviour is identical with or without it.

Only what BitLocker needs is implemented. All multi-byte values BitLocker hands
us are little-endian.
"""

from __future__ import annotations

# ----------------------------------------------------------------- pure AES

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_INV_SBOX = bytes(_INV_SBOX)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p


# precompute mul-by-{2,3,9,11,13,14}
_M2 = bytes(_xtime(i) for i in range(256))
_M3 = bytes(_mul(i, 3) for i in range(256))
_M9 = bytes(_mul(i, 9) for i in range(256))
_M11 = bytes(_mul(i, 11) for i in range(256))
_M13 = bytes(_mul(i, 13) for i in range(256))
_M14 = bytes(_mul(i, 14) for i in range(256))


def _key_expansion(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(words[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        words.append([words[i - nk][j] ^ t[j] for j in range(4)])
    return words


class _PyAES:
    """Single-block AES-128/256 (ECB). State is column-major per FIPS-197."""

    def __init__(self, key: bytes):
        self.nr = {16: 10, 24: 12, 32: 14}[len(key)]
        w = _key_expansion(key)
        # round keys as 16-byte blocks
        self.rk = [bytes(w[4 * r + c][b] for c in range(4) for b in range(4))
                   for r in range(self.nr + 1)]

    def encrypt(self, block: bytes) -> bytes:
        s = bytearray(a ^ b for a, b in zip(block, self.rk[0]))
        for r in range(1, self.nr):
            s = self._round(s, self.rk[r])
        return self._final_round(s, self.rk[self.nr])

    def _round(self, s, rk):
        sb = _SBOX
        # SubBytes + ShiftRows + MixColumns
        t = bytearray(16)
        for c in range(4):
            a0 = sb[s[c * 4 + 0]]
            a1 = sb[s[((c + 1) % 4) * 4 + 1]]
            a2 = sb[s[((c + 2) % 4) * 4 + 2]]
            a3 = sb[s[((c + 3) % 4) * 4 + 3]]
            t[c * 4 + 0] = _M2[a0] ^ _M3[a1] ^ a2 ^ a3
            t[c * 4 + 1] = a0 ^ _M2[a1] ^ _M3[a2] ^ a3
            t[c * 4 + 2] = a0 ^ a1 ^ _M2[a2] ^ _M3[a3]
            t[c * 4 + 3] = _M3[a0] ^ a1 ^ a2 ^ _M2[a3]
        return bytearray(x ^ y for x, y in zip(t, rk))

    def _final_round(self, s, rk):
        sb = _SBOX
        t = bytearray(16)
        for c in range(4):
            t[c * 4 + 0] = sb[s[c * 4 + 0]]
            t[c * 4 + 1] = sb[s[((c + 1) % 4) * 4 + 1]]
            t[c * 4 + 2] = sb[s[((c + 2) % 4) * 4 + 2]]
            t[c * 4 + 3] = sb[s[((c + 3) % 4) * 4 + 3]]
        return bytes(x ^ y for x, y in zip(t, rk))

    def decrypt(self, block: bytes) -> bytes:
        s = bytearray(a ^ b for a, b in zip(block, self.rk[self.nr]))
        s = self._inv_first(s)
        for r in range(self.nr - 1, 0, -1):
            s = bytearray(a ^ b for a, b in zip(s, self.rk[r]))
            s = self._inv_mix(s)
            s = self._inv_first(s)
        return bytes(a ^ b for a, b in zip(s, self.rk[0]))

    def _inv_first(self, s):
        # InvShiftRows then InvSubBytes
        isb = _INV_SBOX
        t = bytearray(16)
        for c in range(4):
            t[c * 4 + 0] = isb[s[c * 4 + 0]]
            t[c * 4 + 1] = isb[s[((c - 1) % 4) * 4 + 1]]
            t[c * 4 + 2] = isb[s[((c - 2) % 4) * 4 + 2]]
            t[c * 4 + 3] = isb[s[((c - 3) % 4) * 4 + 3]]
        return t

    def _inv_mix(self, s):
        t = bytearray(16)
        for c in range(4):
            a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
            t[c * 4 + 0] = _M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3]
            t[c * 4 + 1] = _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3]
            t[c * 4 + 2] = _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3]
            t[c * 4 + 3] = _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3]
        return t


# Prefer the C-backed `cryptography` ECB for speed; identical block semantics.
try:                                                # pragma: no cover - optional
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend as _be

    class _LibAES:
        def __init__(self, key: bytes):
            self._c = Cipher(algorithms.AES(key), modes.ECB(), backend=_be())

        def encrypt(self, block: bytes) -> bytes:
            e = self._c.encryptor()
            return e.update(block) + e.finalize()

        def decrypt(self, block: bytes) -> bytes:
            d = self._c.decryptor()
            return d.update(block) + d.finalize()

    AES = _LibAES
    HAVE_FAST_AES = True
except Exception:                                   # pragma: no cover
    AES = _PyAES
    HAVE_FAST_AES = False


# ----------------------------------------------------------------- helpers

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ----------------------------------------------------------------- AES-CCM

def ccm_decrypt(key: bytes, nonce: bytes, data: bytes, mac_len: int = 16) -> bytes:
    r"""Decrypt+verify a BitLocker AES-CCM blob.

    BitLocker stores key material as: nonce(12) || MAC(16) || ciphertext.
    This takes the key, the 12-byte nonce, and `data` = MAC||ciphertext.
    With a 12-byte nonce the length field is 3 bytes (L=3). Raises ValueError
    if the MAC does not match.
    """
    aes = AES(key)
    mac = data[:mac_len]
    ct = data[mac_len:]
    n = len(ct)
    # CTR keystream: A_i blocks have flags=L-1=2, then nonce, then 3-byte counter.
    plain = bytearray()
    for i in range((n + 15) // 16):
        ctr = bytes([0x02]) + nonce + (i + 1).to_bytes(3, "big")
        ks = aes.encrypt(ctr)
        blk = ct[i * 16:i * 16 + 16]
        plain += _xor(blk, ks[:len(blk)])
    # Verify CBC-MAC: B_0 flags = (M-2)/2 << 3 | (L-1), no AAD.
    flags = (((mac_len - 2) // 2) << 3) | 2
    b0 = bytes([flags]) + nonce + n.to_bytes(3, "big")
    x = aes.encrypt(b0)
    padded = bytes(plain) + b"\x00" * (-n % 16)
    for i in range(0, len(padded), 16):
        x = aes.encrypt(_xor(x, padded[i:i + 16]))
    s0 = aes.encrypt(bytes([0x02]) + nonce + b"\x00\x00\x00")
    tag = _xor(x[:mac_len], s0[:mac_len])
    if tag != mac:
        raise ValueError("AES-CCM MAC verification failed (wrong key?)")
    return bytes(plain)


def ccm_encrypt(key: bytes, nonce: bytes, plain: bytes, mac_len: int = 16) -> bytes:
    """Inverse of ccm_decrypt; returns MAC||ciphertext. For the test builder."""
    aes = AES(key)
    n = len(plain)
    flags = (((mac_len - 2) // 2) << 3) | 2
    b0 = bytes([flags]) + nonce + n.to_bytes(3, "big")
    x = aes.encrypt(b0)
    padded = plain + b"\x00" * (-n % 16)
    for i in range(0, len(padded), 16):
        x = aes.encrypt(_xor(x, padded[i:i + 16]))
    s0 = aes.encrypt(bytes([0x02]) + nonce + b"\x00\x00\x00")
    mac = _xor(x[:mac_len], s0[:mac_len])
    ct = bytearray()
    for i in range((n + 15) // 16):
        ctr = bytes([0x02]) + nonce + (i + 1).to_bytes(3, "big")
        ks = aes.encrypt(ctr)
        blk = plain[i * 16:i * 16 + 16]
        ct += _xor(blk, ks[:len(blk)])
    return mac + bytes(ct)


# ----------------------------------------------------------------- AES-CBC

def cbc_decrypt(aes: "AES", iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(data) - len(data) % 16, 16):
        blk = data[i:i + 16]
        out += _xor(aes.decrypt(blk), prev)
        prev = blk
    return bytes(out)


def cbc_encrypt(aes: "AES", iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(data) - len(data) % 16, 16):
        blk = _xor(data[i:i + 16], prev)
        prev = aes.encrypt(blk)
        out += prev
    return bytes(out)


# ----------------------------------------------------------------- AES-XTS

def _gf_mul_alpha(t: bytearray) -> None:
    """In-place multiply the 128-bit tweak by the primitive element x (GF 2^128)."""
    carry = 0
    for i in range(16):
        b = t[i]
        t[i] = ((b << 1) | carry) & 0xFF
        carry = b >> 7
    if carry:
        t[0] ^= 0x87


def xts_decrypt(aes_data: "AES", aes_tweak: "AES", unit: int, data: bytes) -> bytes:
    """Decrypt one XTS data unit. `unit` is the data-unit (sector) number; the
    tweak is its 128-bit little-endian encoding. Lengths are multiples of 16."""
    tweak = bytearray(unit.to_bytes(16, "little"))
    tweak = bytearray(aes_tweak.encrypt(bytes(tweak)))
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        x = _xor(blk, tweak)
        p = _xor(aes_data.decrypt(x), tweak)
        out += p
        _gf_mul_alpha(tweak)
    return bytes(out)


def xts_encrypt(aes_data: "AES", aes_tweak: "AES", unit: int, data: bytes) -> bytes:
    """Inverse of xts_decrypt. For the test builder."""
    tweak = bytearray(aes_tweak.encrypt(unit.to_bytes(16, "little")))
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        x = _xor(blk, tweak)
        c = _xor(aes_data.encrypt(x), tweak)
        out += c
        _gf_mul_alpha(tweak)
    return bytes(out)


# ------------------------------------------------------- Elephant diffuser
# AES-CBC + Elephant diffuser (Vista/7 default). Operates on the sector as an
# array of 32-bit little-endian words. Constants per the BitLocker spec.

def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


_DIFFUSER_A_RC = (9, 0, 13, 0)
_DIFFUSER_B_RC = (0, 10, 0, 25)


# Forward (encrypt) runs index 0->n-1 adding; inverse runs n-1->0 subtracting,
# which exactly reverses each cycle including the modular wraparound feeds.

def _diffuser_a_encrypt(w: list[int]) -> None:
    n = len(w)
    for _ in range(5):
        for i in range(n):
            w[i] = (w[i] + (w[(i + 2) % n] ^ _rotl32(w[(i + 5) % n], _DIFFUSER_A_RC[i % 4]))) & 0xFFFFFFFF


def _diffuser_a_decrypt(w: list[int]) -> None:
    n = len(w)
    for _ in range(5):
        for i in range(n - 1, -1, -1):
            w[i] = (w[i] - (w[(i + 2) % n] ^ _rotl32(w[(i + 5) % n], _DIFFUSER_A_RC[i % 4]))) & 0xFFFFFFFF


def _diffuser_b_encrypt(w: list[int]) -> None:
    n = len(w)
    for _ in range(3):
        for i in range(n):
            w[i] = (w[i] + (w[(i + n - 2) % n] ^ _rotl32(w[(i + n - 5) % n], _DIFFUSER_B_RC[i % 4]))) & 0xFFFFFFFF


def _diffuser_b_decrypt(w: list[int]) -> None:
    n = len(w)
    for _ in range(3):
        for i in range(n - 1, -1, -1):
            w[i] = (w[i] - (w[(i + n - 2) % n] ^ _rotl32(w[(i + n - 5) % n], _DIFFUSER_B_RC[i % 4]))) & 0xFFFFFFFF


def diffuser_decrypt(data: bytes, sector_key: bytes) -> bytes:
    """Diffuser stage of decrypt: undo B, undo A, then XOR the sector key.
    Input is the AES-CBC-decrypted sector."""
    w = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    _diffuser_b_decrypt(w)
    _diffuser_a_decrypt(w)
    out = b"".join(x.to_bytes(4, "little") for x in w)
    return _xor(out, sector_key)


def diffuser_encrypt(data: bytes, sector_key: bytes) -> bytes:
    """Diffuser stage of encrypt: XOR the sector key, apply A, then B.
    Output is fed to AES-CBC-encrypt."""
    data = _xor(data, sector_key)
    w = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    _diffuser_a_encrypt(w)
    _diffuser_b_encrypt(w)
    return b"".join(x.to_bytes(4, "little") for x in w)
