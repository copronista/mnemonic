# mnemonic

A single-file, pure-stdlib Python CLI that generates **Electrum (4.8)** or
**BIP39** mnemonics (12-24 words), derives the first receiving addresses, and
prints the master/account extended keys (`xprv`/`xpub`, `yprv`/`ypub`,
`zprv`/`zpub`) for mainnet, testnet, signet, or regtest.

No dependencies, no build. Runs on Python 3 with the standard library only.

## Usage

```bash
python3 mnemonic.py --bitshex <hex> --type <electrum|bip39>
```

Exactly one entropy option (`--bits*`) may be given. If none is given, random
entropy is read from `/dev/random` (fallback `os.urandom`). Padding and
truncation always happen **at bit level**:

- input **shorter** than required → cryptographically secure random bits appended
- input **longer** → truncated to the required length

The required size is the BIP39 word count × 8 bits (128-256 bits), or 256 bits
for Electrum. The `Entropy` line reports the source and the user/padding split
in bits, plus the effective entropy in hex, so results are reproducible.

## Options

| Option | Description |
| --- | --- |
| `--bits` | Binary digits (`0`/`1`), MSB-first. |
| `--bits6` | Base-6 digits (`0`-`5`), treated as a big-endian number. |
| `--bitsphrase` | UTF-8 text, encoded as its bytes. |
| `--bitshex` | Hex digits, optional `0x` prefix; leading zero bits kept. |
| `--type` | `electrum` or `bip39` (required). |
| `--electrum-version` | `standard` \| `segwit` \| `2fa` \| `2fa_segwit` (default `segwit`). |
| `--bip39-derivation` | `bip44` \| `bip49` \| `bip84` (default `bip84`). |
| `--bip39-words` | `12` \| `15` \| `18` \| `21` \| `24` (default `24`, BIP39 only). |
| `--network` | `mainnet` \| `testnet` \| `signet` \| `regtest` (default `mainnet`). |
| `--wordlist-file` | Path to the 2048-word list (default `english.txt`, required). |
| `--count` | Number of receiving addresses to display (default 20). |

## Examples

```bash
# BIP39, 24 words, deterministic entropy
python3 mnemonic.py \
  --bitshex 0000000000000000000000000000000000000000000000000000000000000000 \
  --type bip39

# Electrum segwit from a short phrase (padded with random bits)
python3 mnemonic.py --bitsphrase "my seed text" --type electrum

# BIP39, 12 words, testnet, segwit addresses
python3 mnemonic.py --bits6 2103 --type bip39 --bip39-words 12 --network testnet
```

## Standalone binary

`build_binary.sh` produces a self-contained Linux ELF with PyInstaller. The
binary bundles both the Python runtime and `english.txt`, so it runs on a
machine with no Python installed:

```bash
./build_binary.sh
dist/mnemonic --bitshex 0000000000000000000000000000000000000000000000000000000000000000 --type bip39
```

## Testing

```bash
./test_against_electrum.sh            # mainnet; override: NETWORK=testnet COUNT=10
NETWORK=regtest BITS=<64 hex chars> ./test_against_electrum.sh
```

The integration test starts an isolated Electrum 4.8 daemon (from
`../bal/electrum`, override with `ELECTRUM_REPO`) and compares the derived
receiving addresses against the daemon's `listaddresses`. 2FA seeds are
skipped: 2FA wallets are 2-of-3 multisig with a trusted cosigner server, so a
single-key script cannot reproduce their addresses.

## License

[MIT](LICENSE) — © 2026 copronista.
