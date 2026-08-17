#!/usr/bin/env python3
"""
Generate Electrum (4.8) or BIP39 mnemonics from user or random entropy, derive the first
receiving addresses, and display master/account extended private/public keys
(xprv/xpub/yprv/ypub/zprv/zpub).
Supports mainnet, testnet, signet, and regtest via --network.
"""

__author__ = "copronista"
__email__ = "copronista@proton.me"

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import unicodedata

# ---------- Elliptic curve secp256k1 ----------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def inv_mod(a, p=P):
    return pow(a, -1, p) if a % p != 0 else 0

def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv_mod(2 * y1) % P
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mult(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1: result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

def pubkey_from_privkey(privkey_bytes):
    k = int.from_bytes(privkey_bytes, 'big')
    if k <= 0 or k >= N: raise ValueError("Invalid private key")
    x, y = ec_mult(k)
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

# ---------- BIP32 ----------
def bip32_master_key(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def bip32_child_private(k_parent, c_parent, index):
    if index >= 0x80000000:
        data = b'\x00' + k_parent + index.to_bytes(4, 'big')
    else:
        pub = pubkey_from_privkey(k_parent)
        data = pub + index.to_bytes(4, 'big')
    I = hmac.new(c_parent, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    child_key = (int.from_bytes(IL, 'big') + int.from_bytes(k_parent, 'big')) % N
    return child_key.to_bytes(32, 'big'), IR

def bip32_derive_path(key, chaincode, path_list):
    for index in path_list:
        key, chaincode = bip32_child_private(key, chaincode, index)
    return key, chaincode

def bip32_fingerprint_from_privkey(privkey_bytes):
    return hash160(pubkey_from_privkey(privkey_bytes))[:4]

def format_path(indices):
    """Format BIP32 indices as a derivation path, e.g. m/84'/0'/0'."""
    parts = []
    for idx in indices:
        if idx & 0x80000000:
            parts.append(f"{idx & 0x7FFFFFFF}'")
        else:
            parts.append(str(idx))
    return "m/" + "/".join(parts)

# ---------- Base58Check and bech32 ----------
def base58check_encode(payload):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = alphabet[rem] + encoded
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return '1' * pad + encoded

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, witness_version, witness_program):
    data = [witness_version]
    acc = 0
    bits = 0
    for byte in witness_program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits > 0:
        data.append((acc << (5 - bits)) & 31)
    checksum = bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join('qpzry9x8gf2tvdw0s3jn54khce6mua7l'[d] for d in data + checksum)

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

NETWORKS = {
    'mainnet': {'p2pkh': b'\x00', 'p2sh': b'\x05', 'hrp': 'bc'},
    'testnet': {'p2pkh': b'\x6f', 'p2sh': b'\xc4', 'hrp': 'tb'},
    'signet':  {'p2pkh': b'\x6f', 'p2sh': b'\xc4', 'hrp': 'tb'},
    'regtest': {'p2pkh': b'\x6f', 'p2sh': b'\xc4', 'hrp': 'bcrt'},
}

def pubkey_to_address(pubkey_bytes, addr_type, network='mainnet'):
    net = NETWORKS[network]
    if addr_type == 'p2pkh':
        return base58check_encode(net['p2pkh'] + hash160(pubkey_bytes))
    elif addr_type == 'p2sh-p2wpkh':
        redeem_script = b'\x00\x14' + hash160(pubkey_bytes)
        return base58check_encode(net['p2sh'] + hash160(redeem_script))
    elif addr_type == 'p2wpkh':
        return bech32_encode(net['hrp'], 0, hash160(pubkey_bytes))
    raise ValueError("Unknown address type")

# ---------- Extended key serialization ----------
VERSION_BYTES = {
    'bip44': {'mainnet': (0x0488ADE4.to_bytes(4, 'big'), 0x0488B21E.to_bytes(4, 'big')),   # xprv / xpub
              'testnet': (0x04358394.to_bytes(4, 'big'), 0x043587CF.to_bytes(4, 'big'))},  # tprv / tpub
    'bip49': {'mainnet': (0x049D7878.to_bytes(4, 'big'), 0x049D7CB2.to_bytes(4, 'big')),   # yprv / ypub
              'testnet': (0x044A4E28.to_bytes(4, 'big'), 0x044A5262.to_bytes(4, 'big'))},  # uprv / upub
    'bip84': {'mainnet': (0x04B2430C.to_bytes(4, 'big'), 0x04B24746.to_bytes(4, 'big')),   # zprv / zpub
              'testnet': (0x045F18BC.to_bytes(4, 'big'), 0x045F1CF6.to_bytes(4, 'big'))},  # vprv / vpub
    'default': {'mainnet': (0x0488ADE4.to_bytes(4, 'big'), 0x0488B21E.to_bytes(4, 'big')),
                'testnet': (0x04358394.to_bytes(4, 'big'), 0x043587CF.to_bytes(4, 'big'))}
}

def bip32_xprv(privkey_bytes, chain_code, depth, parent_fp, child_num, ver_bytes=VERSION_BYTES['default']['mainnet'][0]):
    payload = ver_bytes + bytes([depth]) + parent_fp + child_num.to_bytes(4, 'big') + chain_code + b'\x00' + privkey_bytes
    return base58check_encode(payload)

def bip32_xpub(privkey_bytes, chain_code, depth, parent_fp, child_num, ver_bytes=VERSION_BYTES['default']['mainnet'][1]):
    payload = ver_bytes + bytes([depth]) + parent_fp + child_num.to_bytes(4, 'big') + chain_code + pubkey_from_privkey(privkey_bytes)
    return base58check_encode(payload)

# ---------- Mnemonic generation ----------
ELECTRUM_VERSIONS = {
    'standard':   '01',
    'segwit':     '100',
    '2fa':        '101',
    '2fa_segwit': '102',
}

def bundled_wordlist_path():
    """Return the wordlist bundled inside a frozen executable, if any."""
    if getattr(sys, 'frozen', False):
        base = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        return os.path.join(base, 'english.txt')
    return None

def load_wordlist(path, fallback=None):
    for candidate in [path] + ([fallback] if fallback is not None else []):
        try:
            with open(candidate, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
            if len(words) != 2048:
                raise ValueError(f"Wordlist must contain 2048 words, found {len(words)}")
            return words
        except FileNotFoundError:
            continue
    print(f"Error: Wordlist file '{path}' not found.", file=sys.stderr)
    sys.exit(1)

def _check_chars(s, allowed, base_name):
    if not s:
        raise ValueError(f"--{base_name} must contain at least one {allowed} digit.")
    bad = next((c for c in s if c not in allowed), None)
    if bad is not None:
        raise ValueError(f"Invalid {base_name} digit {bad!r} in --{base_name}; only {allowed} allowed.")

def binary_to_bits(s):
    _check_chars(s, '01', 'bits')
    return int(s, 2), len(s)

def base6_to_bits(s):
    _check_chars(s, '012345', 'bits6')
    n = int(s, 6)
    return n, n.bit_length()

def hex_to_bits(s):
    if s.startswith(('0x', '0X')):
        s = s[2:]
    _check_chars(s, '0123456789abcdefABCDEF', 'bitshex')
    return int(s, 16), len(s) * 4

def phrase_to_bits(s):
    data = s.encode('utf-8')
    return int.from_bytes(data, 'big'), len(data) * 8

def complete_entropy(value, user_bits, required_bits):
    """Return exactly 'required_bits' bits of entropy.

    User bits are kept MSB-first; if they are fewer than required, random
    bits are appended after them (bit-level padding), otherwise the user
    bits are truncated to the required length. The result always holds
    'required_bits' bits, which is a multiple of 8.
    """
    if user_bits >= required_bits:
        return value >> (user_bits - required_bits)
    pad_bits = required_bits - user_bits
    rand = int.from_bytes(random_entropy_bytes((pad_bits + 7) // 8), 'big')
    return (value << pad_bits) | (rand & ((1 << pad_bits) - 1))

def random_entropy_bytes(size=32):
    # Exactly 'size' bytes of entropy from the kernel CSPRNG
    try:
        with open('/dev/random', 'rb') as f:
            out = bytearray()
            while len(out) < size:
                chunk = f.read(size - len(out))
                if not chunk:
                    break
                out.extend(chunk)
            if len(out) == size:
                return bytes(out)
            raise OSError('short read from /dev/random')
    except OSError:
        return os.urandom(size)

BIP39_WORD_COUNTS = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}  # words -> entropy bytes

def bip39_mnemonic(entropy_bytes, wordlist):
    if len(entropy_bytes) % 4 != 0 or not (16 <= len(entropy_bytes) <= 32):
        raise ValueError("BIP39 entropy must be 128-256 bits in 32-bit multiples.")
    checksum_bits = len(entropy_bytes) * 8 // 32
    checksum = hashlib.sha256(entropy_bytes).digest()[0] >> (8 - checksum_bits)
    total_bits = len(entropy_bytes) * 8 + checksum_bits
    value = (int.from_bytes(entropy_bytes, 'big') << checksum_bits) | checksum
    bit_str = bin(value)[2:].zfill(total_bits)
    return ' '.join(wordlist[int(bit_str[i:i+11], 2)] for i in range(0, total_bits, 11))

def prepare_seed(seed):
    seed = unicodedata.normalize('NFKD', seed).lower()
    return re.sub(r'\s+', ' ', seed).strip()

def mnemonic_encode(number, wordlist):
    words = []
    while number > 0:
        number, remainder = divmod(number, 2048)
        words.append(wordlist[remainder])
    return ' '.join(words)

def electrum_mnemonic(entropy_bytes_full, wordlist, version='segwit'):
    target_prefix = ELECTRUM_VERSIONS[version]
    val = int.from_bytes(entropy_bytes_full[:17], 'big') >> 4
    if val < (2048 ** 11):
        val += (2048 ** 11)
    
    i = 0
    while True:
        phrase = mnemonic_encode(val + i, wordlist)
        clean_phrase = prepare_seed(phrase)
        hmac_val = hmac.new(b"Seed version", clean_phrase.encode('utf-8'), hashlib.sha512).hexdigest()
        
        if hmac_val.startswith(target_prefix):
            return phrase
        i += 1

# ---------- Seed derivation ----------
def bip39_seed_from_mnemonic(mnemonic, passphrase=''):
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), ('mnemonic' + passphrase).encode('utf-8'), 2048, 64)

def electrum_seed_from_mnemonic(mnemonic, passphrase=''):
    clean_phrase = prepare_seed(mnemonic)
    # Electrum uses 'electrum' + passphrase as the PBKDF2 salt
    return hashlib.pbkdf2_hmac('sha512', clean_phrase.encode('utf-8'), ('electrum' + passphrase).encode('utf-8'), 2048, 64)

# ---------- Address derivation ----------
def derive_bip32_wallet(seed, derivation='bip84', count=20, network='mainnet'):
    master_key, master_chain = bip32_master_key(seed)

    if derivation == 'bip44':
        purpose, addr_type = 44, 'p2pkh'
    elif derivation == 'bip49':
        purpose, addr_type = 49, 'p2sh-p2wpkh'
    else:
        purpose, addr_type = 84, 'p2wpkh'
    coin_type = 1 if network != 'mainnet' else 0
    path = [purpose | 0x80000000, coin_type | 0x80000000, 0x80000000]

    account_key, account_chain = bip32_derive_path(master_key, master_chain, path)
    ext_key, ext_chain = bip32_child_private(account_key, account_chain, 0)

    addresses = [pubkey_to_address(pubkey_from_privkey(bip32_child_private(ext_key, ext_chain, i)[0]), addr_type, network) for i in range(count)]
    return addresses, master_key, master_chain, account_key, account_chain, path

def derive_bip39_addresses(mnemonic, derivation='bip84', count=20, network='mainnet', passphrase=''):
    seed = bip39_seed_from_mnemonic(mnemonic, passphrase)
    return derive_bip32_wallet(seed, derivation, count, network)

def derive_slip39_addresses(master_secret, derivation='bip84', count=20, network='mainnet'):
    return derive_bip32_wallet(master_secret, derivation, count, network)

def derive_electrum_addresses(mnemonic, version='segwit', count=20, network='mainnet', passphrase=''):
    addr_type = 'p2wpkh' if version in ('segwit', '2fa_segwit') else 'p2pkh'
    seed = electrum_seed_from_mnemonic(mnemonic, passphrase)

    # The seed must go through HMAC-SHA512 with key "Bitcoin seed" (same as BIP39/BIP32)
    master_key, master_chain = bip32_master_key(seed)

    # Electrum seed paths: 'standard' (legacy) derives receiving/change from m/0/i and
    # m/1/i; 'segwit' and '2fa_segwit' derive from the hardened account m/0'/0/i (and
    # m/0'/1/i for change), as implemented in Electrum's keystore.from_seed.
    if version in ('standard', '2fa'):
        account_key, account_chain = master_key, master_chain
    else:
        account_key, account_chain = bip32_child_private(master_key, master_chain, 0x80000000)

    receiving_key, receiving_chain = bip32_child_private(account_key, account_chain, 0)

    addresses = [pubkey_to_address(pubkey_from_privkey(bip32_child_private(receiving_key, receiving_chain, i)[0]), addr_type, network) for i in range(count)]
    return addresses, master_key, master_chain, receiving_key, receiving_chain, [0]

# ---------- SLIP-39 (Shamir's Secret-Sharing for Mnemonic Codes) ----------
# Implements the SLIP-0039 spec: GF(256) Shamir secret sharing, RS1024 checksum,
# Feistel encryption of the master secret, and two-level (group) sharing.
SLIP39_RADIX_BITS = 10
SLIP39_SECRET_INDEX = 255
SLIP39_DIGEST_INDEX = 254
SLIP39_BASE_ITERATION_COUNT = 10000
SLIP39_ROUND_COUNT = 4
SLIP39_ID_LENGTH_BITS = 15
SLIP39_ITERATION_EXP_LENGTH_BITS = 4
SLIP39_EXTENDABLE_FLAG_LENGTH_BITS = 1
SLIP39_INDEX_LENGTH_BITS = 4
SLIP39_CHECKSUM_LENGTH_WORDS = 3
SLIP39_DIGEST_LENGTH_BYTES = 4
SLIP39_CUSTOMIZATION_STRING_NON_EXTENDABLE = b"shamir"
SLIP39_CUSTOMIZATION_STRING_EXTENDABLE = b"shamir_extendable"
SLIP39_WORD_COUNTS = {12: 16, 24: 32}
SLIP39_RS1024_GEN = (0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120)

def _gf256_precompute():
    exp = [0] * 255
    log = [0] * 256
    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i
        poly = (poly << 1) ^ poly  # multiply by the generator (x + 1)
        if poly & 0x100:
            poly ^= 0x11B
    return exp, log

_GF_EXP, _GF_LOG = _gf256_precompute()

def gf256_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] + _GF_LOG[b]) % 255]

def rs1024_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= SLIP39_RS1024_GEN[i] if ((b >> i) & 1) else 0
    return chk

def rs1024_verify_checksum(cs, data):
    return rs1024_polymod(list(cs) + data) == 1

def rs1024_create_checksum(cs, data):
    values = list(cs) + data
    polymod = rs1024_polymod(values + [0, 0, 0]) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(3)]

def _slip39_int_from_indices(indices):
    value = 0
    for index in indices:
        value = (value << SLIP39_RADIX_BITS) + index
    return value

def _slip39_int_to_indices(value, output_length, bits=SLIP39_RADIX_BITS):
    mask = (1 << bits) - 1
    return [(value >> (i * bits)) & mask for i in reversed(range(output_length))]

def slip39_load_wordlist(path, fallback=None):
    for candidate in [path] + ([fallback] if fallback else []):
        try:
            with open(candidate, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            continue
        if len(words) != 1024:
            raise ValueError(f"SLIP-39 wordlist '{candidate}' must contain exactly 1024 words, found {len(words)}")
        return words
    print(f"Error: SLIP-39 wordlist file '{path}' not found.", file=sys.stderr)
    sys.exit(1)

def slip39_bundled_wordlist_path():
    if getattr(sys, 'frozen', False):
        base = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        return os.path.join(base, 'slip39_english.txt')
    return None

def slip39_split_secret(threshold, share_count, secret):
    """Split a secret into `share_count` shares with `threshold` needed to recover."""
    if not (1 <= threshold <= share_count <= 16):
        raise ValueError("Invalid SLIP-39 share scheme: 1 <= threshold <= share_count <= 16")
    if len(secret) * 8 < 128 or len(secret) * 8 % 16 != 0:
        raise ValueError("Invalid SLIP-39 master secret length (must be a multiple of 128 bits)")
    if threshold == 1:
        return [secret] * share_count
    random_part = random_entropy_bytes(len(secret) - SLIP39_DIGEST_LENGTH_BYTES)
    digest = hmac.new(random_part, secret, hashlib.sha256).digest()[:SLIP39_DIGEST_LENGTH_BYTES]
    digest_value = digest + random_part
    random_shares = [random_entropy_bytes(len(secret)) for _ in range(threshold - 2)]
    points = list(enumerate(random_shares)) + [
        (SLIP39_DIGEST_INDEX, digest_value),
        (SLIP39_SECRET_INDEX, secret),
    ]
    shares = list(random_shares)
    for i in range(threshold - 2, share_count):
        shares.append(slip39_interpolate(points, i))
    return shares

def slip39_interpolate(points, x):
    """Lagrange interpolation over GF(256); points is a list of (x_index, value_bytes)."""
    for px, py in points:
        if px == x:
            return py
    length = len(points[0][1])
    log_prod = sum(_GF_LOG[px ^ x] for px, _ in points)
    result = bytes(length)
    for px, py in points:
        log_basis_eval = (log_prod - _GF_LOG[px ^ x] - sum(_GF_LOG[px ^ ox] for ox, _ in points)) % 255
        result = bytes(
            acc ^ (_GF_EXP[(_GF_LOG[val] + log_basis_eval) % 255] if val != 0 else 0)
            for val, acc in zip(py, result)
        )
    return result

def slip39_recover_secret(threshold, shares):
    """Recover a shared secret from `shares` (list of (x_index, value_bytes))."""
    if threshold == 1:
        return shares[0][1]
    secret = slip39_interpolate(shares, SLIP39_SECRET_INDEX)
    digest_share = slip39_interpolate(shares, SLIP39_DIGEST_INDEX)
    digest = digest_share[:SLIP39_DIGEST_LENGTH_BYTES]
    random_part = digest_share[SLIP39_DIGEST_LENGTH_BYTES:]
    if digest != hmac.new(random_part, secret, hashlib.sha256).digest()[:SLIP39_DIGEST_LENGTH_BYTES]:
        raise ValueError("Invalid digest: the recovered SLIP-39 secret failed verification.")
    return secret

def slip39_round_function(i, passphrase_bytes, iteration_exponent, salt, r):
    iterations = (SLIP39_BASE_ITERATION_COUNT << iteration_exponent) // SLIP39_ROUND_COUNT
    return hashlib.pbkdf2_hmac('sha256', bytes([i]) + passphrase_bytes, salt + r, iterations, len(r))

def slip39_encrypt_master_secret(master_secret, passphrase, iteration_exponent, identifier, extendable=True):
    half = len(master_secret) // 2
    l, r = master_secret[:half], master_secret[half:]
    passphrase_bytes = passphrase.encode('utf-8')
    salt = b'' if extendable else SLIP39_CUSTOMIZATION_STRING_NON_EXTENDABLE + identifier.to_bytes(2, 'big')
    for i in range(SLIP39_ROUND_COUNT):
        l, r = r, bytes(x ^ y for x, y in zip(l, slip39_round_function(i, passphrase_bytes, iteration_exponent, salt, r)))
    return r + l

def slip39_decrypt_master_secret(ems, passphrase, iteration_exponent, identifier, extendable):
    half = len(ems) // 2
    l, r = ems[:half], ems[half:]
    passphrase_bytes = passphrase.encode('utf-8')
    salt = b'' if extendable else SLIP39_CUSTOMIZATION_STRING_NON_EXTENDABLE + identifier.to_bytes(2, 'big')
    for i in reversed(range(SLIP39_ROUND_COUNT)):
        l, r = r, bytes(x ^ y for x, y in zip(l, slip39_round_function(i, passphrase_bytes, iteration_exponent, salt, r)))
    return r + l

def slip39_encode_share(identifier, extendable, iteration_exponent, group_index, group_threshold, group_count, member_index, member_threshold, share_value, wordlist):
    value_bits = len(share_value) * 8
    word_count = (value_bits + SLIP39_RADIX_BITS - 1) // SLIP39_RADIX_BITS
    value_int = int.from_bytes(share_value, 'big')
    value_words = [(value_int >> (SLIP39_RADIX_BITS * i)) & 1023 for i in reversed(range(word_count))]

    metadata = (identifier << 25) | (int(extendable) << 24) | (iteration_exponent << 20) \
        | (group_index << 16) | ((group_threshold - 1) << 12) | ((group_count - 1) << 8) \
        | (member_index << 4) | (member_threshold - 1)
    metadata_words = [(metadata >> (10 * i)) & 1023 for i in reversed(range(4))]

    data = metadata_words + value_words
    cs = SLIP39_CUSTOMIZATION_STRING_EXTENDABLE if extendable else SLIP39_CUSTOMIZATION_STRING_NON_EXTENDABLE
    words = [wordlist[w] for w in data + rs1024_create_checksum(cs, data)]
    return ' '.join(words)

def slip39_decode_share(mnemonic, wordlist):
    indices = []
    for word in mnemonic.split():
        try:
            indices.append(wordlist.index(word.lower()))
        except ValueError:
            raise ValueError(f"Invalid SLIP-39 word: {word!r}") from None
    if len(indices) < 20:
        raise ValueError(f"SLIP-39 share too short ({len(indices)} words); expected at least 20")

    id_ext_exp = _slip39_int_from_indices(indices[:2])
    cs = SLIP39_CUSTOMIZATION_STRING_EXTENDABLE if (id_ext_exp >> 4) & 1 else SLIP39_CUSTOMIZATION_STRING_NON_EXTENDABLE
    if not rs1024_verify_checksum(cs, indices):
        raise ValueError("Invalid SLIP-39 checksum.")

    meta = _slip39_int_from_indices(indices[2:4])
    return {
        'identifier': id_ext_exp >> 5,
        'extendable': bool((id_ext_exp >> 4) & 1),
        'iteration_exponent': id_ext_exp & 0xF,
        'group_index': meta >> 16,
        'group_threshold': ((meta >> 12) & 0xF) + 1,
        'group_count': ((meta >> 8) & 0xF) + 1,
        'member_index': (meta >> 4) & 0xF,
        'member_threshold': (meta & 0xF) + 1,
        'value': _slip39_decode_value(indices[4:-SLIP39_CHECKSUM_LENGTH_WORDS]),
    }

def _slip39_decode_value(value_data):
    padding_len = (SLIP39_RADIX_BITS * len(value_data)) % 16
    if padding_len > 8:
        raise ValueError("Invalid SLIP-39 share length.")
    if value_data[0] >= (1 << (SLIP39_RADIX_BITS - padding_len)):
        raise ValueError("Invalid SLIP-39 padding.")
    value_byte_count = (SLIP39_RADIX_BITS * len(value_data) - padding_len) // 8
    return _slip39_int_from_indices(value_data).to_bytes(value_byte_count, 'big')

def slip39_generate_shares(master_secret, passphrase, group_threshold, group_count, member_threshold, member_count, wordlist, iteration_exponent=0, extendable=True):
    if not (1 <= member_threshold <= member_count <= 16):
        raise ValueError("Invalid SLIP-39 member scheme: 1 <= member_threshold <= member_count <= 16")
    if not (1 <= group_threshold <= group_count <= 16):
        raise ValueError("Invalid SLIP-39 group scheme: 1 <= group_threshold <= group_count <= 16")
    if member_threshold == 1 and member_count > 1:
        raise ValueError("A 1-of-N SLIP-39 group must have exactly one member share")
    if not all(32 <= ord(c) <= 126 for c in passphrase):
        raise ValueError("SLIP-39 passphrase must contain only printable ASCII characters")
    identifier = int.from_bytes(random_entropy_bytes(2), 'big') & 0x7FFF
    ems = slip39_encrypt_master_secret(master_secret, passphrase, iteration_exponent, identifier, extendable)
    group_secrets = slip39_split_secret(group_threshold, group_count, ems)
    shares = []
    for gi in range(group_count):
        member_secrets = slip39_split_secret(member_threshold, member_count, group_secrets[gi])
        for mi in range(member_count):
            shares.append(slip39_encode_share(
                identifier, extendable, iteration_exponent, gi, group_threshold, group_count,
                mi, member_threshold, member_secrets[mi], wordlist))
    return shares

def slip39_recover(shares, passphrase, wordlist):
    parsed = [slip39_decode_share(s, wordlist) for s in shares]
    common = {(p['identifier'], p['extendable'], p['iteration_exponent'], p['group_threshold'], p['group_count']) for p in parsed}
    if len(common) != 1:
        raise ValueError("SLIP-39 shares do not share the same identifier and scheme")
    identifier, extendable, iteration_exponent, group_threshold, _ = next(iter(common))

    groups = {}
    for p in parsed:
        if p['group_count'] < p['group_threshold']:
            raise ValueError("SLIP-39 share declares fewer groups than its group threshold")
        group = groups.setdefault(p['group_index'], (p['member_threshold'], []))
        if group[0] != p['member_threshold']:
            raise ValueError("SLIP-39 shares within a group must have the same member threshold")
        group[1].append((p['member_index'], p['value']))
    for gi, (member_threshold, members) in groups.items():
        if len({m for m, _ in members}) != len(members):
            raise ValueError(f"Duplicate SLIP-39 member share index in group {gi}")
        if len(members) < member_threshold:
            raise ValueError(f"Insufficient SLIP-39 shares in group {gi}: need {member_threshold}, got {len(members)}")

    full_groups = {gi: (mt, members) for gi, (mt, members) in groups.items() if len(members) >= mt}
    if len(full_groups) < group_threshold:
        raise ValueError(f"Insufficient SLIP-39 groups: need {group_threshold}, got {len(full_groups)}")

    group_secrets = [(gi, slip39_recover_secret(mt, members)) for gi, (mt, members) in full_groups.items()]
    ems = slip39_recover_secret(group_threshold, group_secrets)
    return slip39_decrypt_master_secret(ems, passphrase, iteration_exponent, identifier, extendable)

def build_bip32_wallet(seed, derivation, network, passphrase, count):
    """Derive BIP32 wallet and return addresses, keys, and wallet metadata."""
    addresses, master_key, master_chain, account_key, account_chain, path = derive_bip32_wallet(seed, derivation, count, network)
    script = {'bip44': 'p2pkh', 'bip49': 'p2sh-segwit', 'bip84': 'segwit'}[derivation]
    net_key = 'testnet' if network != 'mainnet' else 'mainnet'
    v_prv, v_pub = VERSION_BYTES.get(derivation, VERSION_BYTES['default'])[net_key]
    parent_key, parent_chain = bip32_derive_path(master_key, master_chain, path[:-1])
    account_parent_fp = bip32_fingerprint_from_privkey(parent_key)
    account_xprv = bip32_xprv(account_key, account_chain, len(path), account_parent_fp, path[-1], ver_bytes=v_prv)
    account_xpub = bip32_xpub(account_key, account_chain, len(path), account_parent_fp, path[-1], ver_bytes=v_pub)
    return {
        'script': script,
        'derivation': {'receiving': format_path(path + [0]) + '/i', 'change': format_path(path + [1]) + '/i'},
        'account_xprv': account_xprv,
        'account_xpub': account_xpub,
        'addresses': addresses,
    }


# ---------- Main ----------
def print_human(result, args):
    """Print result dict as human-readable text."""
    t = result['type']
    pp = 'none' if result['passphrase'] is None else '<set>'

    if t == 'electrum':
        print(f"Mnemonic (Electrum {result['version']}):", result['mnemonic'])
        print(f"\nWallet: Electrum {result['version']} ({result['wallet']['script']}) | network {result['network']} | passphrase: {pp}")
        print(f"  Derivation: receiving {result['wallet']['derivation']['receiving']} | change {result['wallet']['derivation']['change']}")
        e = result['entropy']
        if e['hex']:
            print(f"  Entropy {e['note']}: {e['hex']}")
        else:
            print(f"  Entropy: {e['note']}")
        if result['wallet'].get('master_xprv'):
            print("\nMaster xprv:", result['wallet']['master_xprv'])
            print("Master xpub:", result['wallet']['master_xpub'])

    elif t == 'bip39':
        print("Mnemonic (BIP39):", result['mnemonic'])
        print(f"\nWallet: BIP39 {result['derivation']} ({result['wallet']['script']}) | network {result['network']} | passphrase: {pp}")
        print(f"  Derivation: receiving {result['wallet']['derivation']['receiving']} | change {result['wallet']['derivation']['change']}")
        e = result['entropy']
        if e['hex']:
            print(f"  Entropy {e['note']}: {e['hex']}")
        else:
            print(f"  Entropy: {e['note']}")
        print(f"\nAccount xprv (depth 3):", result['wallet']['account_xprv'])
        print(f"Account xpub (depth 3):", result['wallet']['account_xpub'])

    elif t == 'slip39':
        if 'scheme' in result:
            print(f"Mnemonic (SLIP-39 {result['scheme']}):")
            for i, s in enumerate(result['shares'], 1):
                print(f"  Share {i}: {s}")
        else:
            print(f"Recovered SLIP-39 master secret from {result['recovered_from']} shares:")
        print(f"\nWallet: SLIP-39 {result['derivation']} ({result['wallet']['script']}) | network {result['network']} | passphrase: {pp}")
        print(f"  Derivation: receiving {result['wallet']['derivation']['receiving']} | change {result['wallet']['derivation']['change']}")
        if 'entropy' in result:
            print(f"  Master secret {result['entropy']['note']}: {result['entropy']['hex']}")
        else:
            ms = result['master_secret']
            print(f"  Master secret ({len(ms) * 4} bits, from shares): {ms}")
        print(f"\nAccount xprv (depth 3):", result['wallet']['account_xprv'])
        print(f"Account xpub (depth 3):", result['wallet']['account_xpub'])

    if result['addresses']:
        print(f"\nFirst {len(result['addresses'])} addresses:")
        for i, addr in enumerate(result['addresses']): print(f"{i:2d}: {addr}")

# ---------- Partial mnemonic solvers ----------
def _crypto_shuffle(lst):
    """Fisher-Yates shuffle using os.urandom (CSPRNG)."""
    n = len(lst)
    for i in range(n - 1, 0, -1):
        rb = int.from_bytes(os.urandom(4), 'big')
        j = rb % (i + 1)
        lst[i], lst[j] = lst[j], lst[i]

def _parse_partial(partial, wordlist, min_words, radix):
    """Parse a partial mnemonic into known indices and unknown positions."""
    words = partial.split()
    if len(words) < min_words:
        raise ValueError(f"Mnemonic must have at least {min_words} words, got {len(words)}")
    known = {}
    unknown_pos = []
    for i, w in enumerate(words):
        if w == '_':
            unknown_pos.append(i)
        else:
            try:
                known[i] = wordlist.index(w.lower())
            except ValueError:
                raise ValueError(f"Unknown word: {w!r}")
    return len(words), known, unknown_pos

def _iter_solutions(n, known, unknown_pos, radix, check):
    """Iterate over candidate index lists, yielding those passing check(indices)."""
    n_unknown = len(unknown_pos)
    if n_unknown == 0:
        indices = [known.get(i, 0) for i in range(n)]
        if check(indices):
            yield indices
        return
    if n_unknown == 1:
        order = list(range(radix))
        _crypto_shuffle(order)
        for widx in order:
            indices = [0] * n
            for i, idx in known.items():
                indices[i] = idx
            indices[unknown_pos[0]] = widx
            if check(indices):
                yield indices
        return
    seen = set()
    total = radix ** n_unknown
    while len(seen) < total:
        combo = tuple(int.from_bytes(os.urandom(2), 'big') % radix for _ in range(n_unknown))
        if combo in seen:
            continue
        seen.add(combo)
        indices = [0] * n
        for i, idx in known.items():
            indices[i] = idx
        for i, idx in zip(unknown_pos, combo):
            indices[i] = idx
        if check(indices):
            yield indices

def solve_electrum_mnemonic(partial, wordlist, version='segwit'):
    """Solve a partial Electrum mnemonic by brute-forcing unknown words (_)."""
    n, known, unknown_pos = _parse_partial(partial, wordlist, 12, 2048)
    target_prefix = ELECTRUM_VERSIONS[version]
    def check(indices):
        val = 0
        for idx in reversed(indices):
            val = val * 2048 + idx
        if val < (2048 ** 11):
            return False
        phrase = ' '.join(wordlist[idx] for idx in indices)
        clean = prepare_seed(phrase)
        hmac_val = hmac.new(b"Seed version", clean.encode('utf-8'), hashlib.sha512).hexdigest()
        return hmac_val.startswith(target_prefix)
    for indices in _iter_solutions(n, known, unknown_pos, 2048, check):
        return ' '.join(wordlist[idx] for idx in indices)
    return None

def solve_bip39_mnemonic(partial, wordlist):
    """Solve a partial BIP39 mnemonic by brute-forcing unknown words (_) and checking SHA256 checksum."""
    n, known, unknown_pos = _parse_partial(partial, wordlist, 12, 2048)
    if n not in BIP39_WORD_COUNTS:
        raise ValueError(f"BIP39 mnemonic must have {sorted(BIP39_WORD_COUNTS)} words, got {n}")
    entropy_bytes_len = BIP39_WORD_COUNTS[n]
    checksum_bits = entropy_bytes_len * 8 // 32
    def check(indices):
        value = 0
        for idx in indices:
            value = (value << 11) | idx
        entropy_value = value >> checksum_bits
        checksum_value = value & ((1 << checksum_bits) - 1)
        entropy_bytes = entropy_value.to_bytes(entropy_bytes_len, 'big')
        expected = hashlib.sha256(entropy_bytes).digest()[0] >> (8 - checksum_bits)
        return checksum_value == expected
    for indices in _iter_solutions(n, known, unknown_pos, 2048, check):
        return ' '.join(wordlist[idx] for idx in indices)
    return None

def solve_slip39_mnemonic(partial, wordlist):
    """Solve a partial SLIP-39 mnemonic by brute-forcing unknown words (_) and checking RS1024 checksum."""
    n, known, unknown_pos = _parse_partial(partial, wordlist, 20, 1024)
    id_ext_exp = _slip39_int_from_indices([known.get(0, 0), known.get(1, 0)])
    cs = SLIP39_CUSTOMIZATION_STRING_EXTENDABLE if (id_ext_exp >> 4) & 1 else SLIP39_CUSTOMIZATION_STRING_NON_EXTENDABLE
    def check(indices):
        return rs1024_verify_checksum(cs, indices)
    for indices in _iter_solutions(n, known, unknown_pos, 1024, check):
        return ' '.join(wordlist[idx] for idx in indices)
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Generate an Electrum, BIP39 or SLIP-39 mnemonic and derive its first receiving addresses and extended keys.',
        epilog='Entropy inputs shorter than the required size get random bits appended; longer ones are truncated. '
               'Without any --bits* option, random entropy is used.')
    entropy_group = parser.add_mutually_exclusive_group()
    entropy_group.add_argument('--bits', help='binary digits, e.g. "1010"')
    entropy_group.add_argument('--bits6', help='base-6 digits, e.g. "2103"')
    entropy_group.add_argument('--bitsphrase', help='UTF-8 text encoded as its bytes')
    entropy_group.add_argument('--bitshex', help='hex digits, optional 0x prefix, e.g. "0x1a2b"')
    entropy_group.add_argument('--bitsmnemonic', help='partial mnemonic with _ for unknown words, e.g. "abandon _ mimic ..."')
    parser.add_argument('--type', required=True, choices=['electrum', 'bip39', 'slip39'], help='mnemonic algorithm')
    parser.add_argument('--electrum-version', default='segwit', choices=ELECTRUM_VERSIONS.keys(), help='Electrum seed version')
    parser.add_argument('--bip39-derivation', default='bip84', choices=['bip44', 'bip49', 'bip84'], help='derivation scheme; sets key versions and address type')
    parser.add_argument('--bip39-words', type=int, default=24, choices=sorted(BIP39_WORD_COUNTS), help='word count; sets entropy size (BIP39 only)')
    parser.add_argument('--network', default='mainnet', choices=NETWORKS.keys(), help='network the addresses and keys are derived for')
    parser.add_argument('--wordlist-file', default='english.txt', help='2048-word list used for encoding')
    parser.add_argument('--count', type=int, default=20, help='number of receiving addresses to display')
    parser.add_argument('--passphrase', default='', help='BIP39/SLIP-39 passphrase or Electrum extension word; shown as "<set>" when given')
    parser.add_argument('--slip39-words', type=int, default=24, choices=sorted(SLIP39_WORD_COUNTS), help='master secret size in words (12 = 128 bits, 24 = 256 bits)')
    parser.add_argument('--slip39-shares', type=int, default=3, help='number of member shares to generate')
    parser.add_argument('--slip39-threshold', type=int, default=2, help='member shares needed to recover a group')
    parser.add_argument('--slip39-groups', type=int, default=1, help='number of groups (1 = no group sharing)')
    parser.add_argument('--slip39-group-threshold', type=int, default=1, help='groups needed to recover the master secret')
    parser.add_argument('--slip39-wordlist', default='slip39_english.txt', help='1024-word SLIP-39 list used for encoding')
    parser.add_argument('--slip39-recover', action='append', default=None, metavar='MNEMONIC',
                        help='recover a master secret from a SLIP-39 share; repeat for each share')
    parser.add_argument('--json', action='store_true', help='output result as JSON instead of human-readable text')
    args = parser.parse_args()

    result = {
        'network': args.network,
        'passphrase': args.passphrase or None,
        'addresses': [],
    }

    if args.bitsmnemonic:
        if args.type == 'slip39':
            slip_fallback = slip39_bundled_wordlist_path() if args.slip39_wordlist == 'slip39_english.txt' else None
            slip_wordlist = slip39_load_wordlist(args.slip39_wordlist, fallback=slip_fallback)
            solved = solve_slip39_mnemonic(args.bitsmnemonic, slip_wordlist)
            if not solved:
                print("Error: no valid SLIP-39 share found for the given pattern.", file=sys.stderr)
                sys.exit(1)
            if not args.json:
                print(f"Solved SLIP-39 share: {solved}")
            else:
                print(json.dumps({'type': 'slip39', 'solved_share': solved}))
            return

        fallback = bundled_wordlist_path() if args.wordlist_file == 'english.txt' else None
        wordlist = load_wordlist(args.wordlist_file, fallback=fallback)
        if args.type == 'electrum':
            solved = solve_electrum_mnemonic(args.bitsmnemonic, wordlist, args.electrum_version)
        else:
            solved = solve_bip39_mnemonic(args.bitsmnemonic, wordlist)
        if not solved:
            print(f"Error: no valid {args.type} mnemonic found for the given pattern.", file=sys.stderr)
            sys.exit(1)
        missing_bits = args.bitsmnemonic.count('_') * 11
        if not args.json:
            print(f"Solved mnemonic: {solved}")
        args.mnemonic = solved
        args.bitsmnemonic = None
    else:
        wordlist = None
        slip_wordlist = None

    if args.type == 'slip39':
        if slip_wordlist is None:
            slip_fallback = slip39_bundled_wordlist_path() if args.slip39_wordlist == 'slip39_english.txt' else None
            slip_wordlist = slip39_load_wordlist(args.slip39_wordlist, fallback=slip_fallback)

        if args.slip39_recover:
            ms = slip39_recover(args.slip39_recover, args.passphrase, slip_wordlist)
            result['type'] = 'slip39'
            result['recovered_from'] = len(args.slip39_recover)
            result['master_secret'] = ms.hex()
            result['derivation'] = args.bip39_derivation
            wallet = build_bip32_wallet(ms, args.bip39_derivation, args.network, args.passphrase, args.count)
            result['wallet'] = {k: v for k, v in wallet.items() if k != 'addresses'}
            result['addresses'] = wallet['addresses']
        else:
            required_bits = SLIP39_WORD_COUNTS.get(args.slip39_words, 32) * 8
            entropy_bytes, entropy_note = resolve_entropy(args, required_bits)
            shares = slip39_generate_shares(entropy_bytes, args.passphrase, args.slip39_group_threshold,
                                            args.slip39_groups, args.slip39_threshold, args.slip39_shares, slip_wordlist)
            scheme = f"{args.slip39_threshold}-of-{args.slip39_shares}"
            if args.slip39_groups > 1:
                scheme = f"{args.slip39_group_threshold}-of-{args.slip39_groups} groups, each {scheme}"
            result['type'] = 'slip39'
            result['scheme'] = scheme
            result['shares'] = shares
            result['derivation'] = args.bip39_derivation
            result['entropy'] = _parse_entropy_note(entropy_note, entropy_bytes.hex())
            wallet = build_bip32_wallet(entropy_bytes, args.bip39_derivation, args.network, args.passphrase, args.count)
            result['wallet'] = {k: v for k, v in wallet.items() if k != 'addresses'}
            result['addresses'] = wallet['addresses']
    else:
        if wordlist is None:
            fallback = bundled_wordlist_path() if args.wordlist_file == 'english.txt' else None
            wordlist = load_wordlist(args.wordlist_file, fallback=fallback)
        solved = getattr(args, 'mnemonic', None)

        if solved:
            mnemonic = solved
        else:
            required_bits = BIP39_WORD_COUNTS.get(args.bip39_words, 32) * 8 if args.type == 'bip39' else 132
            entropy_bytes, entropy_note = resolve_entropy(args, required_bits)
            mnemonic = None

        if args.type == 'bip39':
            if not mnemonic:
                mnemonic = bip39_mnemonic(entropy_bytes, wordlist)
            result['type'] = 'bip39'
            result['mnemonic'] = mnemonic
            result['derivation'] = args.bip39_derivation
            if solved:
                result['entropy'] = {'hex': '', 'user_bits': 0, 'required_bits': missing_bits, 'source': '--bitsmnemonic', 'note': f'{missing_bits} bits missing from mnemonic', 'detail': ''}
            else:
                result['entropy'] = _parse_entropy_note(entropy_note, entropy_bytes.hex())
            seed = bip39_seed_from_mnemonic(mnemonic, args.passphrase)
            wallet = build_bip32_wallet(seed, args.bip39_derivation, args.network, args.passphrase, args.count)
            result['wallet'] = {k: v for k, v in wallet.items() if k != 'addresses'}
            result['addresses'] = wallet['addresses']
        else:
            if not mnemonic:
                mnemonic = electrum_mnemonic(entropy_bytes, wordlist, args.electrum_version)
            addresses, master_key, master_chain, _, _, _ = derive_electrum_addresses(mnemonic, args.electrum_version, args.count, args.network, args.passphrase)
            if args.electrum_version in ('standard', '2fa'):
                recv_path, change_path, script = 'm/0/i', 'm/1/i', 'p2pkh'
            else:
                recv_path, change_path, script = "m/0'/0/i", "m/0'/1/i", 'p2wpkh'
            net_key = 'testnet' if args.network != 'mainnet' else 'mainnet'
            wallet = {'script': script, 'derivation': {'receiving': recv_path, 'change': change_path}}
            if master_key is not None:
                v_prv, v_pub = (VERSION_BYTES['bip84'] if args.electrum_version == 'segwit' else VERSION_BYTES['bip44'])[net_key]
                wallet['master_xprv'] = bip32_xprv(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0, ver_bytes=v_prv)
                wallet['master_xpub'] = bip32_xpub(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0, ver_bytes=v_pub)
            result['type'] = 'electrum'
            result['version'] = args.electrum_version
            result['mnemonic'] = mnemonic
            if solved:
                result['entropy'] = {'hex': '', 'user_bits': 0, 'required_bits': missing_bits, 'source': '--bitsmnemonic', 'note': f'{missing_bits} bits missing from mnemonic', 'detail': ''}
            else:
                result['entropy'] = _parse_entropy_note(entropy_note, entropy_bytes.hex())
            result['wallet'] = wallet
            result['addresses'] = addresses

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human(result, args)

def _parse_entropy_note(note, hex_str):
    """Parse '128/132 bits (from --bitshex, 128 user + 4 random)' into structured dict."""
    m = re.match(r'(\d+)/(\d+) bits \(([^)]+)\)', note)
    if not m:
        return {'hex': hex_str, 'user_bits': 0, 'required_bits': 0, 'source': '', 'detail': ''}
    user_bits, required_bits, rest = int(m.group(1)), int(m.group(2)), m.group(3)
    parts = rest.split(', ', 1)
    source = parts[0]
    detail = parts[1] if len(parts) > 1 else ''
    return {'hex': hex_str, 'user_bits': user_bits, 'required_bits': required_bits, 'source': source, 'note': note, 'detail': detail}

def resolve_entropy(args, required_bits):
    """Build the effective entropy of exactly `required_bits` from the --bits* options (or random)."""
    byte_length = (required_bits + 7) // 8
    if args.bits is not None:
        user_value, user_bits, source = *binary_to_bits(args.bits), '--bits'
    elif args.bits6 is not None:
        user_value, user_bits, source = *base6_to_bits(args.bits6), '--bits6'
    elif args.bitsphrase is not None:
        user_value, user_bits, source = *phrase_to_bits(args.bitsphrase), '--bitsphrase'
    elif args.bitshex is not None:
        user_value, user_bits, source = *hex_to_bits(args.bitshex), '--bitshex'
    else:
        user_value, user_bits, source = None, 0, None

    if user_value is None:
        return random_entropy_bytes(byte_length), f"{0}/{required_bits} bits (/dev/random)"
    eff = min(user_bits, required_bits)
    if user_bits == required_bits:
        entropy_value = user_value
        detail = ''
    else:
        entropy_value = complete_entropy(user_value, user_bits, required_bits)
        if user_bits > required_bits:
            detail = ''
        else:
            detail = f', {user_bits} user + {required_bits - user_bits} random'
    return entropy_value.to_bytes(byte_length, 'big'), f"{eff}/{required_bits} bits (from {source}{detail})"

if __name__ == '__main__':
    main()
