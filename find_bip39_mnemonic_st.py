# Copyright (c) 2023 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#
# Imports
#
import functools
import itertools
import logging
import logging.handlers
import operator
import os
import shutil
import time
from typing import Any, Dict, List, TextIO, Tuple, Type

from bip_utils import (
    Bip32Slip10Secp256k1, Bip39Languages, Bip39Mnemonic, Bip39MnemonicDecoder, Bip39SeedGenerator, Bip44, Bip44Changes,
    Bip44Coins, EthAddrEncoder, MnemonicChecksumError
)
from bip_utils.addr.iaddr_encoder import IAddrEncoder


#
# Configuration
#

# BIP32
BIP32_ENABLED: bool = True
BIP32_DERIVATION_PATHS: Tuple[str, ...] = (
    "m/44'/0'/0'",
    "m/44'/60'/0'",
)
BIP32_ADDRESSES_NUM: int = 1
BIP32_ADDR_ENCODER_CLS: Type[IAddrEncoder] = EthAddrEncoder
BIP32_ADDR_ENCODER_PARAMS: Dict[str, Any] = {}

# BIP44
BIP44_ENABLED: bool = True
BIP44_COIN: Bip44Coins = Bip44Coins.ETHEREUM
BIP44_CHANGE: Bip44Changes = Bip44Changes.CHAIN_EXT
BIP44_ACCOUNTS_NUM: int = 1
BIP44_ADDRESSES_NUM: int = 1

# Mnemonic
MNEMONIC_PASSPHRASES: Tuple[str, ...] = (
    "",
    "test",
)
MNEMONIC_FIXED: str = ""
MNEMONIC_WORDS: Tuple[List[str], ...] = (
    ["void", "volcano", "volume"],
    ["come"],
    ["effort"],
    ["suffer"],
    ["camp", "camera"],
    ["survey"],
    ["warrior", "warm"],
    ["heavy", "heart", "head"],
    ["shoot"],
    ["primary", "print"],
    ["clutch", "cluster"],
    ["crush", "crunch"],
    ["open"],
    ["amazing", "among", "amount", "amused"],
    ["screen", "scrap"],
    ["patrol", "patient"],
    ["group"],
    ["space", "spare", "spatial"],
    ["point"],
    ["ten"],
    ["exist", "exit"],
    ["slush", "slow"],
    ["involve", "invest", "invite"],
    ["unfold", "unfair"],
)

# Others
ADDRESSES_TO_SEARCH: Tuple[str, ...] = (
    "0x0000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000001",
)
VERBOSE: bool = True

# Output
OUT_FOLDER: str = "results"
OUT_FILE_NAME: str = "results_st"
OUT_FILE_NAME_MAX_SIZE: int = 1024*1024*1024


#
# Functions
#

def get_total_mnemonic_combinations() -> int:
    if MNEMONIC_FIXED != "":
        return 1
    return functools.reduce(operator.mul, [len(words) for words in MNEMONIC_WORDS], 1)


def get_total_addresses() -> int:
    bip32_addr_num = len(BIP32_DERIVATION_PATHS) * BIP32_ADDRESSES_NUM if BIP32_ENABLED else 0
    bip44_addr_num = BIP44_ADDRESSES_NUM * BIP44_ACCOUNTS_NUM if BIP44_ENABLED else 0
    total_addr_num = (bip32_addr_num + bip44_addr_num) * len(MNEMONIC_PASSPHRASES)

    return get_total_mnemonic_combinations() * total_addr_num


def format_integer(num: int) -> str:
    return f"{num:,}".replace(",", ".")


def get_header() -> str:
    return """
**************************************
****                              ****
***                                ***
**                                  **
*          Mnemonic finder           *
*    Author: Emanuele Bellocchia     *
**                                  **
***                                ***
****                              ****
**************************************
"""


def configure_logger() -> None:
    # Create output folder
    shutil.rmtree(OUT_FOLDER, ignore_errors=True)
    os.makedirs(OUT_FOLDER, exist_ok=True)
    # Configure logger handler
    fh = logging.handlers.RotatingFileHandler(os.path.join(OUT_FOLDER, OUT_FILE_NAME),
                                              maxBytes=OUT_FILE_NAME_MAX_SIZE,
                                              backupCount=10000)
    fh.setFormatter(logging.Formatter("%(message)s"))
    # Configure logger
    logging.getLogger("").setLevel(logging.DEBUG if VERBOSE else logging.INFO)
    logging.getLogger("").addHandler(fh)


def log(msg: str) -> None:
    logging.info(msg)


def log_verbose(msg: str) -> None:
    logging.debug(msg)


def derive_bip32_addresses(mnemonic: Bip39Mnemonic,
                           passphrase: str) -> bool:
    if not BIP32_ENABLED:
        return False

    log_verbose(f"Mnemonic: {mnemonic}, passphrase: {passphrase}")

    for path in BIP32_DERIVATION_PATHS:
        log_verbose(f"  BIP32 Derivation path: {path}")

        bip32_ctx = Bip32Slip10Secp256k1.FromSeedAndPath(
            Bip39SeedGenerator(mnemonic).Generate(passphrase),
            path
        )
        for i in range(0, BIP32_ADDRESSES_NUM):
            addr = BIP32_ADDR_ENCODER_CLS.EncodeKey(
                bip32_ctx.DerivePath(str(i)).PublicKey().KeyObject(),
                **BIP32_ADDR_ENCODER_PARAMS
            )
            log_verbose(f"    BIP32 Address {i}: {addr}")
            if addr in ADDRESSES_TO_SEARCH:
                log(f"    Found: {addr}, mnemonic: {mnemonic}, passphrase: {passphrase}")
                return True
    return False


def derive_bip44_addresses(mnemonic: Bip39Mnemonic,
                           passphrase: str) -> bool:
    if not BIP44_ENABLED:
        return False

    log_verbose(f"Mnemonic: {mnemonic}, passphrase: {passphrase}")

    bip44_ctx = Bip44.FromSeed(
        Bip39SeedGenerator(mnemonic).Generate(passphrase),
        BIP44_COIN
    ).Purpose().Coin()
    for i in range(0, BIP44_ACCOUNTS_NUM):
        log_verbose(f"  BIP44 Account: {i}")

        bip44_chg_ctx = bip44_ctx.Account(i).Change(BIP44_CHANGE)
        for j in range(0, BIP44_ADDRESSES_NUM):
            addr = bip44_chg_ctx.AddressIndex(j).PublicKey().ToAddress()
            log_verbose(f"    BIP44 Address {j}: {addr}")
            if addr in ADDRESSES_TO_SEARCH:
                log(f"    Found: {addr}, mnemonic: {mnemonic}, passphrase: {passphrase}")
                return True
    return False


def check_mnemonic(mnemonic: Bip39Mnemonic) -> bool:
    try:
        Bip39MnemonicDecoder(Bip39Languages.ENGLISH).Decode(mnemonic)
    except MnemonicChecksumError:
        pass
    else:
        for passphrase in MNEMONIC_PASSPHRASES:
            if derive_bip32_addresses(mnemonic, passphrase):
                return True
            if derive_bip44_addresses(mnemonic, passphrase):
                return True

    return False


def find_mnemonic() -> None:
    for mnemonic_list in itertools.product(*MNEMONIC_WORDS):
        mnemonic = Bip39Mnemonic.FromList(mnemonic_list)
        if check_mnemonic(mnemonic):
            print(f"  Found: {mnemonic}")
            return


#
# Main
#
def main() -> None:
    total_addresses = get_total_addresses()

    print(get_header())
    print(f"Total mnemonic combinations: {format_integer(get_total_mnemonic_combinations())}")
    print(f"Total derived addresses: {format_integer(total_addresses)}")
    input("Press a key to start")
    print("")

    configure_logger()

    if total_addresses == 0:
        print("No address to check, exiting...")
        return

    start_time = time.time()

    if MNEMONIC_FIXED != "":
        check_mnemonic(Bip39Mnemonic.FromString(MNEMONIC_FIXED))
    else:
        print("Processing...")
        find_mnemonic()

    print(f"Elapsed time: {time.time() - start_time:.2f} sec")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
