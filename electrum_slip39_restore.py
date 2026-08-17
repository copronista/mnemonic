#!/usr/bin/env python3
"""Create an Electrum wallet file from SLIP-39 mnemonic shares.

Electrum's CLI `restore` command only accepts Electrum-type seeds, so SLIP-39
import has to go through the same code path the GUI wizard uses:
slip39.recover_ems() + EncryptedSeed.decrypt() + keystore.from_bip43_rootseed().
The resulting wallet file is then loaded by the Electrum daemon.

Run with the Electrum virtualenv python:
  env/bin/python electrum_slip39_restore.py --mnemonic '...' --mnemonic '...' \
      --derivation m/84h/0h/0h --passphrase '...' \
      --electrum-path /tmp/eldir --wallet /tmp/eldir/wallet
"""

__author__ = "copronista"
__email__ = "copronista@proton.me"

import argparse

from electrum import SimpleConfig, keystore
from electrum.slip39 import recover_ems
from electrum.storage import WalletStorage
from electrum.util import create_and_start_event_loop
from electrum.wallet import Wallet
from electrum.wallet_db import WalletDB


def xtype_from_derivation(derivation: str) -> str:
    if "m/84h" in derivation:
        return "p2wpkh"
    if "m/49h" in derivation:
        return "p2wpkh-p2sh"
    return "standard"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mnemonic", action="append", required=True,
                        help="one SLIP-39 share; repeat for each share")
    parser.add_argument("--passphrase", default="")
    parser.add_argument("--derivation", default="m/84h/0h/0h")
    parser.add_argument("--electrum-path", required=True)
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--chain", default="mainnet", choices=["mainnet", "testnet", "signet", "regtest"])
    args = parser.parse_args()

    config_options = {"electrum_path": args.electrum_path}
    if args.chain != "mainnet":
        config_options[args.chain] = True
    config = SimpleConfig(config_options)
    # record the correct genesis block hash in the wallet file
    config.get_selected_chain().set_as_network()
    storage = WalletStorage(args.wallet, allow_partial_writes=False)
    db = WalletDB("", storage=storage, upgrade=True)

    # wallet.synchronize() requires a running asyncio event loop
    loop, _stop_loop, loop_thread = create_and_start_event_loop()

    root_seed = recover_ems(args.mnemonic).decrypt(args.passphrase)
    keystore_instance = keystore.from_bip43_rootseed(
        root_seed,
        derivation=args.derivation,
        xtype=xtype_from_derivation(args.derivation),
    )
    db.put("keystore", keystore_instance.dump())
    db.put("wallet_type", "standard")

    wallet = Wallet(db, config=config)
    wallet.synchronize()
    wallet.save_db()
    loop.call_soon_threadsafe(_stop_loop.set_result, 1)
    loop_thread.join(timeout=1)


if __name__ == "__main__":
    main()
