# Introduction

Simple utility application to help recover a lost BIP39 mnemonic based on my [bip_utils](https://github.com/ebellocchia/bip_utils) library.

# Background Story

A friend of mine had a Trezor wallet that, as you probably know, only generates 12-word mnemonics (yep, there is a workaround for it, but it's for advanced users).\
Since he wanted to use a 24-word one, he generated it externally and then initialized the Trezor with it.\
So far so good, but there are two "little problems":

1. When recovering a wallet, the Trezor doesn't ask to insert the mnemonic a second time for confirmation
2. While typing the mnemonic words, the Trezor suggests similar ones to speed up the process

He had used wallets many times before and inserting a mnemonic was nothing special for him.\
So, he didn't pay too much attention and accidentally selected some wrong words among the suggested ones, still getting a valid mnemonic (the BIP39 checksum is pretty weak).\
Then, he transferred some funds to an Ethereum address (not the first one) for long-term holding and finally initialized the Trezor with another mnemonic for everyday use.

Everything was fine until he decided to recover the initial mnemonic to move some of the funds. This time he inserted the correct one and, as you can guess, he got a totally different address with zero balance.

That's when he called me for help.

# Description

The application is pretty simple: given a list of possible words for each mnemonic word, the application generates all combinations (i.e. it computes the Cartesian product) and it derives addresses for each valid mnemonic, searching for the target ones.\
Both standard BIP44 derivation paths and custom BIP32 paths can be derived, using different passphrases for seed computation.

I coded two versions of the application:

- `find_bip39_mnemonic_st.py`: simple implementation with a single thread doing everything
- `find_bip39_mnemonic_mp.py`: it uses the Python `multiprocessing` module to split the work among multiple processes

I also implemented a version using the `threading` module, but ended up not using it because of the poor Python thread performace.

# Configuration

To configure the application, just edit the configuration part on the top of the file. The configuration variables are described below.

|Configuration Name|Description|
|---|---|
|`BIP32_ENABLED`|If true, addresses will be derived using BIP32 derivation paths|
|`BIP32_DERIVATION_PATHS`|List of BIP32 derivation paths to be used|
|`BIP32_ADDRESSES_NUM`|Number of addresses to be derived for each derivation path in `BIP32_DERIVATION_PATHS`|
|`BIP32_ADDR_ENCODER_CLS`|Encoder class to encode public keys to addresses|
|`BIP32_ADDR_ENCODER_PARAMS`|Dictionary containing additional parameters for the encoder address class, if any. Refer to the [bip_utils](https://github.com/ebellocchia/bip_utils) documentation for the specific address class parameters.|
|`BIP44_ENABLED`|If true, addresses will be derived using BIP44 derivation paths|
|`BIP44_COIN`|BIP44 coin to be used (`Bip44Coins` type)|
|`BIP44_CHANGE`|BIP44 change to be used (`Bip44Changes` type)|
|`BIP44_ACCOUNTS_NUM`|Number of accounts to be derived (`m/44'/coin'/account'`)|
|`BIP44_ADDRESSES_NUM`|Number of addresses to be derived for each account (`m/44'/coin'/account'/change/address`)|
|`MNEMONIC_PASSPHRASES`|List of passphrases to compute the seed from the mnemonic|
|`MNEMONIC_FIXED`|If specified, the application only checks this mnemonic and then exits. Useful to check a single specific mnemonic.|
|`MNEMONIC_WORDS`|List of possible words for each mnemonic word. The length of the list shall be a valid mnemonic length (e.g. 12, 25, 24). The default value is just an example, you shall modify it.|
|`ADDRESSES_TO_SEARCH`|List of addresses to be searched. The addresses shall be related to the same mnemonic.|
|`VERBOSE`|If true, all derived address will be written to the `OUT_FILE_NAME` file. If false, the mnemonic will be written only when the correct one is found.|
|`OUT_FOLDER`|Output folder where the result files will be written to|
|`OUT_FILE_NAME`|Output file name where results are written to|
|`OUT_FILE_NAME_MAX_SIZE`|Maximum size of the output file. When the size is reached, a new file will be created.|

The multiprocessing application (i.e. `find_bip39_mnemonic_mp.py`) uses queues for inter-process communication, so there is some additional configuration:

|Configuration Name|Description|
|---|---|
|`LOG_QUEUE_MAX_SIZE`|Maximum size of the mnemonic queue. The size is in elements, which are logging strings in this case. You can leave the default value.|
|`MNEMONIC_QUEUE_MAX_SIZE`|Maximum size of the mnemonic queue. The size is in elements, which are mnemonic strings in this case. This determines the maximum RAM consumption of the application, you can try different values by monitoring it (e.g. using task manager). The default value should use around 4Gb of RAM.|
|`PROCESS_NUM`|Number of processes to be used|

# Install and Run

To install the dependencies, just run in the application folder:

    pip install -r requirements.txt

To run the application, just run the desidered script:

    python find_bip39_mnemonic_st.py

Or:

    python find_bip39_mnemonic_mp.py
