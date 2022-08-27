//! Constants for the Pirate test network.

/// The testnet coin type for ARRR, as defined by [SLIP 44].
///
/// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const COIN_TYPE: u32 = 141;

/// The HRP for a Bech32-encoded testnet [`ExtendedSpendingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedSpendingKey`]: crate::zip32::ExtendedSpendingKey
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-test";

/// The HRP for a Bech32-encoded testnet [`ExtendedFullViewingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedFullViewingKey`]: crate::zip32::ExtendedFullViewingKey
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewtestsapling";

/// The HRP for a Bech32-encoded testnet [`PaymentAddress`].
///
/// Defined in section 5.6.4 of the [Zcash Protocol Specification].
///
/// [`PaymentAddress`]: crate::sapling::PaymentAddress
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "ztestsapling";

/// The prefix for a Base58Check-encoded testnet [`TransparentAddress::PublicKey`].
///
/// [`TransparentAddress::PublicKey`]: crate::legacy::TransparentAddress::PublicKey
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 1] = [0x00];

/// The prefix for a Base58Check-encoded testnet [`TransparentAddress::Script`].
///
/// [`TransparentAddress::Script`]: crate::legacy::TransparentAddress::Script
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 1] = [0x05];
