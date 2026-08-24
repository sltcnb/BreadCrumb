"""Build a synthetic BitLocker (FVE) disk image for tests.

Produces a byte image whose layout mirrors a real BitLocker volume closely
enough to exercise breadcrumb.bitlocker's real parse + key-recovery + decrypt path:
an FVE boot sector with metadata offsets, an FVE metadata block carrying a
recovery-password VMK protector and a VMK-wrapped FVEK, encrypted data sectors,
and a relocated backup of the original boot sector.
"""

import struct

from breadcrumb import _aes, bitlocker

SS = 512


def _entry(etype, vtype, data, version=1):
    return struct.pack("<HHHH", 8 + len(data), etype, vtype, version) + data


def _ccm_entry(etype, vtype, key, payload, nonce):
    blob = nonce + _aes.ccm_encrypt(key, nonce, payload)
    return _entry(etype, vtype, blob)


def build_image(plaintext_volume: bytes, recovery_password: str,
                method: int = bitlocker.M_AES_XTS_128,
                nest_ccm_in_stretch: bool = True) -> bytes:
    """Build an FVE image.

    nest_ccm_in_stretch puts the AES-CCM wrapped VMK inside the stretch-key
    entry, which is how Windows writes it; False puts the two side by side, the
    layout this test builder used to assume. Both must unlock.
    """
    assert len(plaintext_volume) % SS == 0
    n_sectors = len(plaintext_volume) // SS

    keylen = {
        bitlocker.M_AES_XTS_128: 32, bitlocker.M_AES_XTS_256: 64,
        bitlocker.M_AES_CBC_128: 16, bitlocker.M_AES_CBC_256: 32,
        bitlocker.M_AES_CBC_128_DIFFUSER: 32, bitlocker.M_AES_CBC_256_DIFFUSER: 64,
    }[method]
    fvek = bytes((i * 7 + 3) & 0xFF for i in range(keylen))
    vmk = bytes((i * 5 + 1) & 0xFF for i in range(32))
    cipher = bitlocker._Cipher(method, fvek, SS)

    meta_off = n_sectors * SS
    backup_off = meta_off + 0x10000

    # --- encrypt data sectors (sector 0 is relocated; 1..n-1 in place) ---
    img = bytearray(backup_off + SS)
    for i in range(1, n_sectors):
        pt = plaintext_volume[i * SS:(i + 1) * SS]
        img[i * SS:(i + 1) * SS] = cipher._encrypt_sector(i, pt)
    # backup of original boot sector, encrypted with its relocated sector no.
    img[backup_off:backup_off + SS] = cipher._encrypt_sector(
        backup_off // SS, plaintext_volume[:SS])

    # --- FVE boot sector (sector 0) ---
    boot = bytearray(SS)
    boot[3:11] = bitlocker.FVE_SIGNATURE
    struct.pack_into("<H", boot, 11, SS)
    for k in range(3):
        struct.pack_into("<Q", boot, 0x160 + k * 8, meta_off)
    boot[510:512] = b"\x55\xaa"
    img[0:SS] = boot

    # --- FVE metadata block ---
    salt = bytes(range(16))
    secret = bitlocker.parse_recovery_password(recovery_password)
    dk = bitlocker.stretch_key(bitlocker._password_hash(secret), salt)
    nonce_v = b"\x10" * 12
    nonce_f = b"\x20" * 12

    vmk_ccm = _ccm_entry(0, bitlocker.VT_AES_CCM_KEY, dk,
                         b"\x01\x00\x00\x00" + vmk, nonce_v)
    if nest_ccm_in_stretch:
        stretch = _entry(0, bitlocker.VT_STRETCH_KEY,
                         b"\x00\x00\x00\x00" + salt + vmk_ccm)
        protector = stretch
    else:
        stretch = _entry(0, bitlocker.VT_STRETCH_KEY, b"\x00\x00\x00\x00" + salt)
        protector = stretch + vmk_ccm
    # VMK entry: identifier GUID(16) last_modified(8) unknown(2)
    # protection_type(2) then the nested protector entries.
    vmk_data = (bytes(range(16))              # identifier GUID
                + b"\x00" * 8                 # last modification time
                + b"\x00\x00"                 # unknown
                + struct.pack("<H", bitlocker.PROT_RECOVERY)
                + protector)
    vmk_entry = _entry(bitlocker.ET_VMK, bitlocker.VT_VMK, vmk_data)
    fvek_entry = _ccm_entry(bitlocker.ET_FVEK, bitlocker.VT_AES_CCM_KEY, vmk,
                            b"\x01\x00" + struct.pack("<H", method) + fvek, nonce_f)

    body = vmk_entry + fvek_entry
    meta_hdr = bytearray(0x30)
    struct.pack_into("<I", meta_hdr, 0, 0x30 + len(body))      # metadata_size
    struct.pack_into("<I", meta_hdr, 0x24, method)             # encryption_method

    block_hdr = bytearray(0x40)
    block_hdr[0:8] = bitlocker.FVE_SIGNATURE
    struct.pack_into("<Q", block_hdr, 0x10, n_sectors * SS)    # encrypted size
    struct.pack_into("<I", block_hdr, 0x1C, 1)                 # header_sectors
    struct.pack_into("<Q", block_hdr, 0x20, backup_off)        # volume_header_offset

    block = bytes(block_hdr) + bytes(meta_hdr) + body
    img[meta_off:meta_off + len(block)] = block
    return bytes(img)
