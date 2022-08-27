//! # Regtest constants
//!
//! `regtest` is a `pirated`-specific environment used for local testing. They mostly reuse
//! the testnet constants.
//! These constants are defined in [the `pirated` codebase].
//!

/// The regtest cointype reuses the testnet cointype
pub const COIN_TYPE: u32 = 141;

/// The HRP for a Bech32-encoded regtest [`ExtendedSpendingKey`].
///
/// It is defined in [the `pirated` codebase].
///
/// [`ExtendedSpendingKey`]: crate::zip32::ExtendedSpendingKey
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-regtest";

/// The HRP for a Bech32-encoded regtest [`ExtendedFullViewingKey`].
///
/// It is defined in [the `pirated` codebase].
///
/// [`ExtendedFullViewingKey`]: crate::zip32::ExtendedFullViewingKey
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewregtestsapling";

/// The HRP for a Bech32-encoded regtest [`PaymentAddress`].
///
/// It is defined in [the `pirated` codebase].
///
/// [`PaymentAddress`]: crate::sapling::PaymentAddress
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zregtestsapling";

/// The prefix for a Base58Check-encoded regtest [`TransparentAddress::PublicKey`].
/// Same as the testnet prefix.
///
/// [`TransparentAddress::PublicKey`]: crate::legacy::TransparentAddress::PublicKey
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 1] = [0x3c];

/// The prefix for a Base58Check-encoded regtest [`TransparentAddress::Script`].
/// Same as the testnet prefix.
///
/// [`TransparentAddress::Script`]: crate::legacy::TransparentAddress::Script
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 1] = [0x55];
