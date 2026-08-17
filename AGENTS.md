# AGENTS.md

Single-file, pure-stdlib Python CLI: generates Electrum (4.8), BIP39, or SLIP-39 mnemonics, derives the first receiving addresses, and prints master/account extended keys (xprv/xpub/yprv/ypub/zprv/zpub). No dependencies, no build. Integration test requires the Electrum source tree at `../bal/electrum`.

## Run

```bash
python3 mnemonic.py --bitshex <hex> --type <electrum|bip39|slip39>
```

- Exactly one entropy option may be given; they are mutually exclusive. If none is given, random entropy is read from `/dev/random` (fallback: `os.urandom`) and printed in hex.
  - `--bits` — binary digits (`0`/`1`), any length; MSB-first, kept exactly as given (no byte alignment).
  - `--bits6` — base-6 digits (`0`-`5`), any length; treated as a big-endian number, its bit length is the number of significant bits.
  - `--bitsphrase` — UTF-8 text, any length; encoded as UTF-8 bits.
  - `--bitshex` — hex digits (optional `0x` prefix), any length; leading zero bits are preserved.
- Entropy length is free. Padding/truncation always happens **at bit level**: if the input is **shorter** than the size the selected algorithm needs (BIP39 word count × 8 bits, or 256 bits for Electrum), cryptographically secure random bits are appended after the user bits; if **longer**, it is truncated to the required number of bits. The final entropy always has exactly the required length (a multiple of 8). The `Entropy` line reports the source and the user/padding or truncation split in bits, and prints the effective entropy in hex so the wallet is reproducible.
- `--type` is required (`electrum` | `bip39` | `slip39`).
- `--electrum-version` (default `segwit`): `standard|segwit|2fa|2fa_segwit`.
- `--bip39-derivation` (default `bip84`): `bip44|bip49|bip84`; selects key versions and address type.
- `--bip39-words` (default `24`, BIP39 only): `12|15|18|21|24`; selects entropy size (128/160/192/224/256 bits). Ignored for `--type electrum`.
- `--network` (default `mainnet`): `mainnet|testnet|signet|regtest`. On non-mainnet, coin type becomes `1'` (testnet/signet share `tb` HRP and testnet key versions; regtest uses `bcrt` HRP).
- `--wordlist-file` defaults to `english.txt` (2048 words, BIP39/Electrum order) in the current directory; the script exits if it is missing.
- `--count` number of addresses to derive (default 20).
- `--passphrase` BIP39/SLIP-39 passphrase or Electrum extension word; SLIP-39 passphrases must contain only printable ASCII (code points 32–126).
- `--slip39-words` (default `24`, SLIP-39 only): `12|24`; selects master secret size (128/256 bits).
- `--slip39-shares` total member shares to generate (default 3, SLIP-39 only).
- `--slip39-threshold` member shares needed per group (default 2, SLIP-39 only).
- `--slip39-groups` number of independent groups (default 1; `--slip39-group-threshold` groups are required to recover).
- `--slip39-group-threshold` groups needed to recover the master secret (default 1).
- `--slip39-wordlist` defaults to `slip39_english.txt` (1024 words) in the current directory.
- `--slip39-recover` repeat for each mnemonic share; pass at least `--slip39-threshold` shares from each of `--slip39-group-threshold` groups. All other `--slip39-*` generation options are ignored.
- All output goes to stdout; nothing is written to disk.

## SLIP-39

SLIP-39 implements Shamir's Secret-Sharing for mnemonic codes (spec: https://github.com/satoshilabs/slips/blob/master/slip-0039.md). A master secret is split into mnemonic word shares using Galois field GF(256) arithmetic, with an RS1024 checksum and optional Feistel encryption. The shares are two-level: group shares can each be split into member shares (e.g. 2-of-3 groups, each 2-of-3 members).

Generation produces the master secret from the `--bits*` entropy input (padded to 128 or 256 bits), then encrypts and splits it. Recovery takes N `--slip39-recover` share mnemonics and a `--passphrase`, decrypts, and derives the same BIP32 wallet. The master secret is the BIP32 seed directly; BIP44/49/84 derivation is reused from the `--bip39-derivation` option.

## Integration test

```bash
./test_slip39.sh                        # SLIP-39 vectors + round-trips + Electrum cross-check
./test_against_electrum.sh              # mainnet; override: NETWORK=testnet COUNT=10
NETWORK=regtest BITS=<64 hex chars> ./test_against_electrum.sh
```

- `test_slip39.sh` runs 12 checks: 45 official Trezor vectors (passphrase `"TREZOR"`), 5 generation/recovery round-trips (1-of-1, 2-of-3, 3-of-5, two-level 2x3; both 128 and 256 bits), and 4 cross-checks against Electrum's own `slip39.recover_ems` (including passphrase).
- `test_against_electrum.sh` starts an isolated Electrum 4.8 daemon (temp `ELECTRUMDIR`, never touches real wallets) from `../bal/electrum` and compares the script's receiving addresses against the daemon's `listaddresses` for the same mnemonic. Override the tree with `ELECTRUM_REPO`.
- `BITS` sets the deterministic entropy for the BIP39 cases (default 256 zero bits); `ELECTRUM_BITS` for the Electrum cases (always 256 bits). `SLIP39_BITS` for the SLIP-39 case. `BIP39_WORDS` (default 24) selects the word count and must match `BITS` length.
- Electrum-type mnemonics are imported with the daemon `restore` command.
- BIP39 mnemonics are imported via `electrum_bip39_restore.py`, which uses Electrum's own wizard code path (`bip39_to_seed` + `from_bip43_rootseed`); the CLI `restore` command does not support BIP39. Addresses still come from the daemon via `load_wallet` + `listaddresses`.
- SLIP-39 shares are imported via `electrum_slip39_restore.py`, which uses `slip39.recover_ems` + `from_bip43_rootseed`; the daemon has no direct SLIP-39 import. 2-of-3 shares are passed (threshold for a single group).
- 2FA seeds are skipped: 2FA wallets are 2-of-3 multisig with a trusted cosigner server, so a single-key script cannot reproduce their addresses.

## Gotchas

- Electrum is not BIP39. Electrum seed = PBKDF2(phrase, salt `electrum`+passphrase), and addresses derive from the master key at `m/0/i` (standard) or `m/0'/0/i` (segwit/2fa_segwit) — no BIP44-style coin-type level. Do not "fix" this to BIP44/84 paths.
- Electrum word encoding (`mnemonic_encode`) uses little-endian remainder order by design; that is correct for Electrum.
- `prepare_seed` NFKD-normalizes, lowercases, and collapses whitespace; this feeds the Electrum `"Seed version"` HMAC prefix check.
- Some inline comments in `mnemonic.py` are Italian; keep all new code and comments in English.
- SLIP-39 is not Electrum's native seed format. SLIP-39 shares recover a master secret which is fed into BIP32 via the standard BIP43 derivation (same as BIP39), not Electrum's PBKDF2-based seed derivation.
- The official Trezor test vectors (`slip39_vectors.json`) use passphrase `"TREZOR"`, not empty.
