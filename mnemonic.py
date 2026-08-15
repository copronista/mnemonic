#!/usr/bin/env python3
"""
Generate Electrum (4.8) or BIP39 mnemonic from 256 bits, derive first 20 receiving addresses,
and display master/account extended private/public keys (xprv/xpub).

Input: 256 bits as binary string (256 chars of 0/1) or hex string (64 chars).
Output: mnemonic phrase, list of 20 addresses, and xprv/xpub.

Usage examples:
  python mnemonic_addr_xkeys.py --bits 000... (binary) --type bip39 --bip39-derivation bip84
  python mnemonic_addr_xkeys.py --bits deadbeef... (hex) --type electrum --electrum-version segwit
"""

import argparse
import hashlib
import hmac
import sys

# ---------- Elliptic curve secp256k1 ----------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def inv_mod(a, p=P):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
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
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

def pubkey_from_privkey(privkey_bytes):
    k = int.from_bytes(privkey_bytes, 'big')
    if k <= 0 or k >= N:
        raise ValueError("Invalid private key")
    point = ec_mult(k)
    x, y = point
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

# ---------- BIP32 ----------
def bip32_master_key(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chaincode = I[:32], I[32:]
    return key, chaincode

def bip32_child_private(k_parent, c_parent, index):
    if index >= 0x80000000:
        data = b'\x00' + k_parent + index.to_bytes(4, 'big')
    else:
        pub = pubkey_from_privkey(k_parent)
        data = pub + index.to_bytes(4, 'big')
    I = hmac.new(c_parent, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    child_key = (int.from_bytes(IL, 'big') + int.from_bytes(k_parent, 'big')) % N
    child_key_bytes = child_key.to_bytes(32, 'big')
    return child_key_bytes, IR

def bip32_derive_path(key, chaincode, path_list):
    for index in path_list:
        key, chaincode = bip32_child_private(key, chaincode, index)
    return key, chaincode

def bip32_fingerprint_from_privkey(privkey_bytes):
    pub = pubkey_from_privkey(privkey_bytes)
    return hash160(pub)[:4]

def bip32_fingerprint_from_pubkey(pubkey_bytes):
    return hash160(pubkey_bytes)[:4]

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
    """Encode a segwit address (BIP173) with proper 5-bit conversion."""
    data = [witness_version]
    # Convert 8-bit witness program to 5-bit groups
    acc = 0
    bits = 0
    for byte in witness_program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits > 0:
        # Pad with zeros to form the last 5-bit group
        data.append((acc << (5 - bits)) & 31)
    # Insert program length (in bytes) as second element
    data.insert(1, len(witness_program))
    checksum = bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join('qpzry9x8gf2tvdw0s3jn54khce6mua7l'[d] for d in data + checksum)

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def pubkey_to_address(pubkey_bytes, addr_type):
    if addr_type == 'p2pkh':
        payload = b'\x00' + hash160(pubkey_bytes)
        return base58check_encode(payload)
    elif addr_type == 'p2sh-p2wpkh':
        redeem_script = b'\x00\x14' + hash160(pubkey_bytes)
        payload = b'\x05' + hash160(redeem_script)
        return base58check_encode(payload)
    elif addr_type == 'p2wpkh':
        return bech32_encode('bc', 0, hash160(pubkey_bytes))
    else:
        raise ValueError("Unknown address type")

# ---------- Extended key serialization ----------
XPRV_VERSION = 0x0488ADE4.to_bytes(4, 'big')
XPUB_VERSION = 0x0488B21E.to_bytes(4, 'big')

def bip32_xprv(privkey_bytes, chain_code, depth, parent_fp, child_num):
    payload = (XPRV_VERSION + bytes([depth]) + parent_fp +
               child_num.to_bytes(4, 'big') + chain_code +
               b'\x00' + privkey_bytes)
    return base58check_encode(payload)

def bip32_xpub(privkey_bytes, chain_code, depth, parent_fp, child_num):
    pub = pubkey_from_privkey(privkey_bytes)
    payload = (XPUB_VERSION + bytes([depth]) + parent_fp +
               child_num.to_bytes(4, 'big') + chain_code + pub)
    return base58check_encode(payload)

# ---------- Mnemonic generation ----------
ELECTRUM_VERSIONS = {
    'standard':   0x0001,
    'segwit':     0x0100,
    '2fa':        0x0101,
    '2fa_segwit': 0x0102,
}

def load_wordlist(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        if len(words) != 2048:
            raise ValueError(f"Wordlist must contain 2048 words, found {len(words)}")
        return words
    except FileNotFoundError:
        print(f"Error: Wordlist file '{path}' not found.", file=sys.stderr)
        sys.exit(1)

def detect_input_type(bits_str):
    if len(bits_str) == 256 and all(c in '01' for c in bits_str):
        return 'binary'
    if len(bits_str) == 64 and all(c in '0123456789abcdefABCDEF' for c in bits_str):
        return 'hex'
    return None

def normalize_to_bytes(bits_str):
    input_type = detect_input_type(bits_str)
    if input_type is None:
        raise ValueError("Input must be either 256 binary digits (0/1) or 64 hex characters.")
    if input_type == 'binary':
        return int(bits_str, 2).to_bytes(32, 'big')
    else:
        return bytes.fromhex(bits_str)

def bip39_mnemonic(entropy_bytes, wordlist):
    if len(entropy_bytes) != 32:
        raise ValueError("BIP39 with 256 bits requires exactly 32 bytes of entropy.")
    checksum_bits = len(entropy_bytes) * 8 // 32
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    checksum = hash_bytes[0] >> (8 - checksum_bits)
    total_bits = len(entropy_bytes) * 8 + checksum_bits
    value = (int.from_bytes(entropy_bytes, 'big') << checksum_bits) | checksum
    bit_str = bin(value)[2:].zfill(total_bits)
    indices = [int(bit_str[i:i+11], 2) for i in range(0, total_bits, 11)]
    return ' '.join(wordlist[i] for i in indices)

def electrum_mnemonic(entropy_bytes_full, wordlist, version='standard'):
    if len(entropy_bytes_full) != 32:
        raise ValueError("Input entropy must be 32 bytes (256 bits).")
    if version not in ELECTRUM_VERSIONS:
        raise ValueError(f"Unknown Electrum version '{version}'.")
    version_int = ELECTRUM_VERSIONS[version]
    entropy_14 = entropy_bytes_full[:14]
    seed_bytes = version_int.to_bytes(2, 'big') + entropy_14
    checksum = hashlib.sha256(seed_bytes).digest()[0] >> 4
    value = (int.from_bytes(seed_bytes, 'big') << 4) | checksum
    bit_str = bin(value)[2:].zfill(132)
    indices = [int(bit_str[i:i+11], 2) for i in range(0, 132, 11)]
    return ' '.join(wordlist[i] for i in indices)

# ---------- Seed derivation ----------
def bip39_seed_from_mnemonic(mnemonic, passphrase=''):
    salt = 'mnemonic' + passphrase
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt.encode('utf-8'), 2048, 64)

def electrum_seed_from_mnemonic(mnemonic, passphrase=''):
    salt = 'electrum' + passphrase
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt.encode('utf-8'), 2048, 64)

# ---------- Address derivation ----------
def derive_bip39_addresses(mnemonic, derivation='bip84', count=20):
    seed = bip39_seed_from_mnemonic(mnemonic)
    master_key, master_chain = bip32_master_key(seed)

    if derivation == 'bip44':
        path = [44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000]
        addr_type = 'p2pkh'
    elif derivation == 'bip49':
        path = [49 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000]
        addr_type = 'p2sh-p2wpkh'
    elif derivation == 'bip84':
        path = [84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000]
        addr_type = 'p2wpkh'
    else:
        raise ValueError(f"Unsupported BIP39 derivation '{derivation}'")

    account_key, account_chain = bip32_derive_path(master_key, master_chain, path)
    ext_key, ext_chain = bip32_child_private(account_key, account_chain, 0)

    addresses = []
    for i in range(count):
        child_key, _ = bip32_child_private(ext_key, ext_chain, i)
        pubkey = pubkey_from_privkey(child_key)
        addresses.append(pubkey_to_address(pubkey, addr_type))
    return addresses, master_key, master_chain, account_key, account_chain, path

def derive_electrum_addresses(mnemonic, version='standard', count=20):
    if version == 'standard':
        addr_type = 'p2pkh'
    elif version == 'segwit':
        addr_type = 'p2wpkh'
    else:
        print(f"Warning: Electrum version '{version}' address derivation not implemented.", file=sys.stderr)
        return [], None, None, None, None, None

    seed = electrum_seed_from_mnemonic(mnemonic)
    master_key, master_chain = seed[:32], seed[32:]

    # Account 0' (hardened)
    account_key, account_chain = bip32_child_private(master_key, master_chain, 0x80000000)

    addresses = []
    for i in range(count):
        child_key, _ = bip32_child_private(account_key, account_chain, i)
        pubkey = pubkey_from_privkey(child_key)
        addresses.append(pubkey_to_address(pubkey, addr_type))

    return addresses, master_key, master_chain, account_key, account_chain, [0x80000000]

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Generate Electrum or BIP39 mnemonic and addresses from 256 bits.")
    parser.add_argument('--bits', required=True, help="256-bit input: binary (256 chars) or hex (64 chars).")
    parser.add_argument('--type', required=True, choices=['electrum', 'bip39'], help="Mnemonic type.")
    parser.add_argument('--electrum-version', default='standard', choices=ELECTRUM_VERSIONS.keys(),
                        help="Electrum wallet type (only for --type electrum). Default: standard.")
    parser.add_argument('--bip39-derivation', default='bip84', choices=['bip44', 'bip49', 'bip84'],
                        help="BIP39 derivation path (only for --type bip39). Default: bip84 (native segwit).")
    parser.add_argument('--wordlist-file', default='english.txt', help="Path to wordlist file.")
    parser.add_argument('--count', type=int, default=20, help="Number of addresses to generate (default 20).")
    args = parser.parse_args()

    wordlist = load_wordlist(args.wordlist_file)

    try:
        entropy_bytes = normalize_to_bytes(args.bits)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.type == 'bip39':
        mnemonic = bip39_mnemonic(entropy_bytes, wordlist)
        print("Mnemonic (BIP39):", mnemonic)
        print(f"Deriving {args.count} addresses using {args.bip39_derivation} path...")
        addresses, master_key, master_chain, account_key, account_chain, path = derive_bip39_addresses(mnemonic, args.bip39_derivation, args.count)

        # Master keys
        master_fp = bip32_fingerprint_from_privkey(master_key)
        master_xprv = bip32_xprv(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0)
        master_xpub = bip32_xpub(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0)

        # Account keys
        parent_key = master_key
        parent_chain = master_chain
        for idx in path[:-1]:
            parent_key, parent_chain = bip32_child_private(parent_key, parent_chain, idx)
        account_parent_fp = bip32_fingerprint_from_privkey(parent_key)
        account_child_num = path[-1]

        account_depth = len(path)
        account_xprv = bip32_xprv(account_key, account_chain, account_depth, account_parent_fp, account_child_num)
        account_xpub = bip32_xpub(account_key, account_chain, account_depth, account_parent_fp, account_child_num)

        print("\nExtended keys (BIP32):")
        print("Master xprv:", master_xprv)
        print("Master xpub:", master_xpub)
        print(f"Account xprv (depth {account_depth}):", account_xprv)
        print(f"Account xpub (depth {account_depth}):", account_xpub)

    else:  # electrum
        mnemonic = electrum_mnemonic(entropy_bytes, wordlist, args.electrum_version)
        print(f"Mnemonic (Electrum {args.electrum_version}):", mnemonic)
        print(f"Deriving {args.count} receiving addresses...")
        addresses, master_key, master_chain, account_key, account_chain, path = derive_electrum_addresses(mnemonic, args.electrum_version, args.count)

        if master_key is not None:
            master_fp = bip32_fingerprint_from_privkey(master_key)
            master_xprv = bip32_xprv(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0)
            master_xpub = bip32_xpub(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0)

            account_parent_fp = master_fp
            account_child_num = 0x80000000
            account_xprv = bip32_xprv(account_key, account_chain, 1, account_parent_fp, account_child_num)
            account_xpub = bip32_xpub(account_key, account_chain, 1, account_parent_fp, account_child_num)

            print("\nExtended keys (BIP32):")
            print("Master xprv:", master_xprv)
            print("Master xpub:", master_xpub)
            print("Account xprv (m/0'):", account_xprv)
            print("Account xpub (m/0'):", account_xpub)
        else:
            print("Extended keys not available (unsupported Electrum version).", file=sys.stderr)

    if addresses:
        print("\nFirst %d addresses:" % len(addresses))
        for i, addr in enumerate(addresses, start=0):
            print(f"{i:2d}: {addr}")
    else:
        print("No addresses generated.", file=sys.stderr)

if __name__ == '__main__':
    main()
