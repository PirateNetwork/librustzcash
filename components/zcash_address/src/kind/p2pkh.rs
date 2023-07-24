/// The prefix for a Base58Check-encoded mainnet transparent P2PKH address.
pub(crate) const MAINNET: [u8; 1] = [0x3c];

/// The prefix for a Base58Check-encoded testnet transparent P2PKH address.
pub(crate) const TESTNET: [u8; 1] = [0x00];

pub(crate) type Data = [u8; 20];
