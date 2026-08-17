# mnemonic

A single-file, pure-stdlib Python CLI that generates **Electrum (4.8)**,
**BIP39**, or **SLIP-39** mnemonics, derives the first receiving addresses, and
prints the master/account extended keys (`xprv`/`xpub`, `yprv`/`ypub`,
`zprv`/`zpub`) for mainnet, testnet, signet, or regtest.

No dependencies, no build. Runs on Python 3 with the standard library only.

## Usage

```bash
python3 mnemonic.py --bitshex <hex> --type <electrum|bip39|slip39>
```

Exactly one entropy option (`--bits*`) may be given. If none is given, random
entropy is read from `/dev/random` (fallback `os.urandom`). Padding and
truncation always happen **at bit level**:

- input **shorter** than required → cryptographically secure random bits appended
- input **longer** → truncated to the required length

The required size is the BIP39 word count × 8 bits (128-256 bits), 256 bits for
Electrum, or 128/256 bits for SLIP-39 (set by `--slip39-words`). The `Entropy`
line reports the source and the user/padding split in bits, plus the effective
entropy in hex, so results are reproducible.

## Options

| Option | Description |
| --- | --- |
| `--bits` | Binary digits (`0`/`1`), MSB-first. |
| `--bits6` | Base-6 digits (`0`-`5`), treated as a big-endian number. |
| `--bitsphrase` | UTF-8 text, encoded as its bytes. |
| `--bitshex` | Hex digits, optional `0x` prefix; leading zero bits kept. |
| `--type` | `electrum`, `bip39`, or `slip39` (required). |
| `--passphrase` | BIP39/SLIP-39 passphrase or Electrum extension word. |
| `--electrum-version` | `standard` \| `segwit` \| `2fa` \| `2fa_segwit` (default `segwit`). |
| `--bip39-derivation` | `bip44` \| `bip49` \| `bip84` (default `bip84`). |
| `--bip39-words` | `12` \| `15` \| `18` \| `21` \| `24` (default `24`, BIP39 only). |
| `--network` | `mainnet` \| `testnet` \| `signet` \| `regtest` (default `mainnet`). |
| `--wordlist-file` | Path to the 2048-word list (default `english.txt`, required). |
| `--count` | Number of receiving addresses to display (default 20). |
| `--slip39-words` | `12` \| `24` (default `24`; SLIP-39 only). Master secret size in words. |
| `--slip39-shares` | Total member shares to generate (default 3). |
| `--slip39-threshold` | Member shares needed to recover a group (default 2). |
| `--slip39-groups` | Number of groups (default 1 = no group sharing). |
| `--slip39-group-threshold` | Groups needed to recover the master secret (default 1). |
| `--slip39-wordlist` | Path to the 1024-word SLIP-39 list (default `slip39_english.txt`). |
| `--slip39-recover` | One mnemonic share to recover from; repeat for each share. |

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

# SLIP-39 2-of-3, 128-bit master secret
python3 mnemonic.py \
  --bitshex 00000000000000000000000000000000 \
  --type slip39 --slip39-words 12 --slip39-threshold 2 --slip39-shares 3

# SLIP-39 recovery (repeat --slip39-recover for each share)
python3 mnemonic.py --type slip39 \
  --slip39-recover "word1 word2 ..." \
  --slip39-recover "word1 word2 ..." \
  --passphrase "my secret"
```

## Standalone binary

`build_binary.sh` produces a self-contained Linux ELF with PyInstaller. The
binary bundles both the Python runtime, `english.txt` and `slip39_english.txt`,
so it runs on a machine with no Python installed:

```bash
./build_binary.sh
dist/mnemonic --bitshex 0000000000000000000000000000000000000000000000000000000000000000 --type bip39
```

## Testing

```bash
./test_slip39.sh                        # SLIP-39 vectors + round-trips + Electrum cross-check
./test_against_electrum.sh              # mainnet; override: NETWORK=testnet COUNT=10
NETWORK=regtest BITS=<64 hex chars> ./test_against_electrum.sh
```

`test_slip39.sh` verifies the SLIP-39 implementation against the 45 official
test vectors from the Trezor reference library, performs generation/recovery
round-trips (1-of-1 through 2-of-2 groups), and cross-checks the recovered
master secret against Electrum's own `slip39.recover_ems`.

The Electrum integration test (`test_against_electrum.sh`) starts an isolated
Electrum 4.8 daemon (from `../bal/electrum`, override with `ELECTRUM_REPO`) and
compares the derived receiving addresses against the daemon's `listaddresses`
for BIP39, Electrum, and SLIP-39 mnemonics. 2FA seeds are skipped: 2FA wallets
are 2-of-3 multisig with a trusted cosigner server, so a single-key script
cannot reproduce their addresses.

## License

[MIT](LICENSE) — © 2026 copronista.
