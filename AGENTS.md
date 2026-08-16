# AGENTS.md

Single-file, pure-stdlib Python CLI: generates Electrum (4.8) or BIP39 mnemonics (12-24 words), derives the first receiving addresses, and prints master/account extended keys (xprv/xpub/yprv/ypub/zprv/zpub). No dependencies, no build. Integration test requires the Electrum source tree at `../bal/electrum`.

## Run

```bash
python3 mnemonic.py --bitshex <hex> --type <electrum|bip39>
```

- Exactly one entropy option may be given; they are mutually exclusive. If none is given, random entropy is read from `/dev/random` (fallback: `os.urandom`) and printed in hex.
  - `--bits` — binary digits (`0`/`1`), any length; MSB-first, kept exactly as given (no byte alignment).
  - `--bits6` — base-6 digits (`0`-`5`), any length; treated as a big-endian number, its bit length is the number of significant bits.
  - `--bitsphrase` — UTF-8 text, any length; encoded as UTF-8 bits.
  - `--bitshex` — hex digits (optional `0x` prefix), any length; leading zero bits are preserved.
- Entropy length is free. Padding/truncation always happens **at bit level**: if the input is **shorter** than the size the selected algorithm needs (BIP39 word count × 8 bits, or 256 bits for Electrum), cryptographically secure random bits are appended after the user bits; if **longer**, it is truncated to the required number of bits. The final entropy always has exactly the required length (a multiple of 8). The `Entropy` line reports the source and the user/padding or truncation split in bits, and prints the effective entropy in hex so the wallet is reproducible.
- `--type` is required (`electrum` | `bip39`).
- `--electrum-version` (default `segwit`): `standard|segwit|2fa|2fa_segwit`.
- `--bip39-derivation` (default `bip84`): `bip44|bip49|bip84`; selects key versions and address type.
- `--bip39-words` (default `24`, BIP39 only): `12|15|18|21|24`; selects entropy size (128/160/192/224/256 bits). Ignored for `--type electrum`.
- `--network` (default `mainnet`): `mainnet|testnet|signet|regtest`. On non-mainnet, coin type becomes `1'` (testnet/signet share `tb` HRP and testnet key versions; regtest uses `bcrt` HRP).
- `--wordlist-file` defaults to `english.txt` (2048 words, BIP39/Electrum order) in the current directory; the script exits if it is missing.
- `--count` number of addresses to derive (default 20).
- All output goes to stdout; nothing is written to disk.

## Integration test

```bash
./test_against_electrum.sh            # mainnet; override: NETWORK=testnet COUNT=10
NETWORK=regtest BITS=<64 hex chars> ./test_against_electrum.sh
```

- Starts an isolated Electrum 4.8 daemon (temp `ELECTRUMDIR`, never touches real wallets) from `../bal/electrum` and compares the script's receiving addresses against the daemon's `listaddresses` for the same mnemonic. Override the tree with `ELECTRUM_REPO`.
- `BITS` sets the deterministic entropy for the BIP39 cases (default 256 zero bits); `ELECTRUM_BITS` for the Electrum cases (always 256 bits). `BIP39_WORDS` (default 24) selects the word count and must match `BITS` length.
- Electrum-type mnemonics are imported with the daemon `restore` command.
- BIP39 mnemonics are imported via `electrum_bip39_restore.py`, which uses Electrum's own wizard code path (`bip39_to_seed` + `from_bip43_rootseed`); the CLI `restore` command does not support BIP39. Addresses still come from the daemon via `load_wallet` + `listaddresses`.
- 2FA seeds are skipped: 2FA wallets are 2-of-3 multisig with a trusted cosigner server, so a single-key script cannot reproduce their addresses.

## Gotchas

- Electrum is not BIP39. Electrum seed = PBKDF2(phrase, salt `electrum`+passphrase), and addresses derive from the master key at `m/0/i` (standard) or `m/0'/0/i` (segwit/2fa_segwit) — no BIP44-style coin-type level. Do not "fix" this to BIP44/84 paths.
- Electrum word encoding (`mnemonic_encode`) uses little-endian remainder order by design; that is correct for Electrum.
- `prepare_seed` NFKD-normalizes, lowercases, and collapses whitespace; this feeds the Electrum `"Seed version"` HMAC prefix check.
- Some inline comments in `mnemonic.py` are Italian; keep all new code and comments in English.
