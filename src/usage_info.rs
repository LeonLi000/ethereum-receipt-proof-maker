pub static USAGE_INFO: &'static str = "
❍ Rusty Receipt Proof Maker ❍

    Copyright Provable 2019
    Questions: greg@oraclize.it

❍ Info ❍

This tool generates a merkle receipt proof of the receipt pertaining to the given transaction hash.

***

Usage:  rusty-receipt-proof-maker [-h | --help]
        rusty-receipt-proof-maker <txhash> [-t | --trace]
        rusty-receipt-proof-maker <txhash> [-v | --verbose]

Options:

    -h, --help          ❍ Show this message.

    -v, --verbose       ❍ Enable verbose mode for additional output.

    -t, --trace         ❍ Enable tracing for debugging/bug reporting.

    <txhash>            ❍ A transaction hash of an Ethereum transaction
                        ➔ Format: A 32-byte long, prefixed hex string.

";
