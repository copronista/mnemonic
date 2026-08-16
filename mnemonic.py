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
    # L'algoritmo Electrum usa 'electrum' + passphrase come salt per la PBKDF2
    return hashlib.pbkdf2_hmac('sha512', clean_phrase.encode('utf-8'), ('electrum' + passphrase).encode('utf-8'), 2048, 64)

# ---------- Address derivation ----------
def derive_bip39_addresses(mnemonic, derivation='bip84', count=20, network='mainnet'):
    seed = bip39_seed_from_mnemonic(mnemonic)
    master_key, master_chain = bip32_master_key(seed)

    if derivation == 'bip44':
        purpose, addr_type = 44, 'p2pkh'
    elif derivation == 'bip49':
        purpose, addr_type = 49, 'p2sh-p2wpkh'
    elif derivation == 'bip84':
        purpose, addr_type = 84, 'p2wpkh'
    coin_type = 1 if network != 'mainnet' else 0
    path = [purpose | 0x80000000, coin_type | 0x80000000, 0x80000000]

    account_key, account_chain = bip32_derive_path(master_key, master_chain, path)
    ext_key, ext_chain = bip32_child_private(account_key, account_chain, 0)

    addresses = [pubkey_to_address(pubkey_from_privkey(bip32_child_private(ext_key, ext_chain, i)[0]), addr_type, network) for i in range(count)]
    return addresses, master_key, master_chain, account_key, account_chain, path

def derive_electrum_addresses(mnemonic, version='segwit', count=20, network='mainnet'):
    addr_type = 'p2wpkh' if version in ('segwit', '2fa_segwit') else 'p2pkh'
    seed = electrum_seed_from_mnemonic(mnemonic)
    
    # QUI ERA L'ERRORE: invece di smezzare i byte generati, devono prima passare per HMAC-SHA512
    # con la chiave "Bitcoin seed" (esattamente come su BIP39/BIP32)
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

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(
        description='Generate an Electrum or BIP39 mnemonic and derive its first receiving addresses and extended keys.',
        epilog='Entropy inputs shorter than the required size get random bits appended; longer ones are truncated. '
               'Without any --bits* option, random entropy is used.')
    entropy_group = parser.add_mutually_exclusive_group()
    entropy_group.add_argument('--bits', help='binary digits, e.g. "1010"')
    entropy_group.add_argument('--bits6', help='base-6 digits, e.g. "2103"')
    entropy_group.add_argument('--bitsphrase', help='UTF-8 text encoded as its bytes')
    entropy_group.add_argument('--bitshex', help='hex digits, optional 0x prefix, e.g. "0x1a2b"')
    parser.add_argument('--type', required=True, choices=['electrum', 'bip39'], help='mnemonic algorithm')
    parser.add_argument('--electrum-version', default='segwit', choices=ELECTRUM_VERSIONS.keys(), help='Electrum seed version')
    parser.add_argument('--bip39-derivation', default='bip84', choices=['bip44', 'bip49', 'bip84'], help='derivation scheme; sets key versions and address type')
    parser.add_argument('--bip39-words', type=int, default=24, choices=sorted(BIP39_WORD_COUNTS), help='word count; sets entropy size (BIP39 only)')
    parser.add_argument('--network', default='mainnet', choices=NETWORKS.keys(), help='network the addresses and keys are derived for')
    parser.add_argument('--wordlist-file', default='english.txt', help='2048-word list used for encoding')
    parser.add_argument('--count', type=int, default=20, help='number of receiving addresses to display')
    args = parser.parse_args()

    fallback = bundled_wordlist_path() if args.wordlist_file == 'english.txt' else None
    wordlist = load_wordlist(args.wordlist_file, fallback=fallback)
    required_bits = BIP39_WORD_COUNTS.get(args.bip39_words, 32) * 8 if args.type == 'bip39' else 256
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
        entropy_bytes = random_entropy_bytes(required_bits // 8)
        entropy_note = f"({required_bits} bits, /dev/random)"
    else:
        if user_bits == required_bits:
            entropy_value = user_value
            note = f"{user_bits} user bits"
        else:
            entropy_value = complete_entropy(user_value, user_bits, required_bits)
            if user_bits > required_bits:
                note = f"truncated from {user_bits} to {required_bits} bits"
            else:
                note = f"{user_bits} user bits + {required_bits - user_bits} random bits"
        entropy_bytes = entropy_value.to_bytes(required_bits // 8, 'big')
        entropy_note = f"({required_bits} bits, from {source}, {note})"
    net_key = 'testnet' if args.network != 'mainnet' else 'mainnet'

    if args.type == 'bip39':
        mnemonic = bip39_mnemonic(entropy_bytes, wordlist)
        print("Mnemonic (BIP39):", mnemonic)
        addresses, master_key, master_chain, account_key, account_chain, path = derive_bip39_addresses(mnemonic, args.bip39_derivation, args.count, args.network)

        script = {'bip44': 'p2pkh', 'bip49': 'p2sh-segwit', 'bip84': 'segwit'}[args.bip39_derivation]
        print(f"\nWallet: BIP39 {args.bip39_derivation} ({script}) | network {args.network} | passphrase: none")
        print(f"  Derivation: receiving {format_path(path + [0])}/i | change {format_path(path + [1])}/i")
        print(f"  Entropy {entropy_note}: {entropy_bytes.hex()}")

        v_prv, v_pub = VERSION_BYTES.get(args.bip39_derivation, VERSION_BYTES['default'])[net_key]
        master_xprv = bip32_xprv(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0, ver_bytes=VERSION_BYTES['bip44'][net_key][0])
        master_xpub = bip32_xpub(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0, ver_bytes=VERSION_BYTES['bip44'][net_key][1])
        
        parent_key, parent_chain = bip32_derive_path(master_key, master_chain, path[:-1])
        account_parent_fp = bip32_fingerprint_from_privkey(parent_key)
        
        account_xprv = bip32_xprv(account_key, account_chain, len(path), account_parent_fp, path[-1], ver_bytes=v_prv)
        account_xpub = bip32_xpub(account_key, account_chain, len(path), account_parent_fp, path[-1], ver_bytes=v_pub)
        
        print(f"\nAccount xprv (depth {len(path)}):", account_xprv)
        print(f"Account xpub (depth {len(path)}):", account_xpub)
    else:
        mnemonic = electrum_mnemonic(entropy_bytes, wordlist, args.electrum_version)
        print(f"Mnemonic (Electrum {args.electrum_version}):", mnemonic)
        addresses, master_key, master_chain, _, _, _ = derive_electrum_addresses(mnemonic, args.electrum_version, args.count, args.network)

        if args.electrum_version in ('standard', '2fa'):
            recv_path, change_path, script = 'm/0/i', 'm/1/i', 'p2pkh'
        else:
            recv_path, change_path, script = "m/0'/0/i", "m/0'/1/i", 'p2wpkh'
        print(f"\nWallet: Electrum {args.electrum_version} ({script}) | network {args.network} | passphrase: none")
        print(f"  Derivation: receiving {recv_path} | change {change_path}")
        print(f"  Entropy {entropy_note}: {entropy_bytes.hex()}")

        if master_key is not None:
            v_prv, v_pub = (VERSION_BYTES['bip84'] if args.electrum_version == 'segwit' else VERSION_BYTES['bip44'])[net_key]
            master_xprv = bip32_xprv(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0, ver_bytes=v_prv)
            master_xpub = bip32_xpub(master_key, master_chain, 0, b'\x00\x00\x00\x00', 0, ver_bytes=v_pub)
            print("\nMaster xprv:", master_xprv)
            print("Master xpub:", master_xpub)

    if addresses:
        print("\nFirst %d addresses:" % len(addresses))
        for i, addr in enumerate(addresses): print(f"{i:2d}: {addr}")

if __name__ == '__main__':
    main()
