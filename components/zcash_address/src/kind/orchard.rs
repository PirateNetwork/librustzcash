// Human-Readable Parts (HRPs) for Bech32-encoded Orchard payment addresses.
//
// These HRP constants match the TreasureChest (Pirate Chain full node) implementation
// as defined in src/chainparams.cpp.
//
// Orchard is the latest shielded protocol upgrade after Sapling, introduced in NU5.
// Orchard addresses use the Pallas curve and provide improved performance and privacy.

/// The HRP for a Bech32-encoded mainnet Orchard payment address.
///
/// Defined in TreasureChest: src/chainparams.cpp line 223
/// Format: bech32HRPs[ORCHARD_PAYMENT_ADDRESS] = "pirate"
///
/// Examples of mainnet Orchard addresses start with "pirate1..."
pub(crate) const MAINNET: &str = "pirate";

/// The HRP for a Bech32-encoded testnet Orchard payment address.
///
/// Defined in TreasureChest: src/chainparams.cpp line 438
/// Format: bech32HRPs[ORCHARD_PAYMENT_ADDRESS] = "pirate-test"
///
/// Examples of testnet Orchard addresses start with "pirate-test1..."
pub(crate) const TESTNET: &str = "pirate-test";

/// The HRP for a Bech32-encoded regtest Orchard payment address.
///
/// Defined in TreasureChest: src/chainparams.cpp line 550
/// Format: bech32HRPs[ORCHARD_PAYMENT_ADDRESS] = "pirate-regtest"
///
/// Examples of regtest Orchard addresses start with "pirate-regtest1..."
pub(crate) const REGTEST: &str = "pirate-regtest";

/// The data payload size for an Orchard payment address.
///
/// Defined in TreasureChest: src/zcash/address/pirate_orchard.hpp line 16
/// Format: const size_t SerializedOrchardPaymentAddressSize = 43;
///
/// An Orchard payment address consists of:
/// - 11 bytes: diversifier (d)
/// - 32 bytes: diversified transmission key (pk_d)
/// Total: 43 bytes
///
/// This matches the Sapling address size, as both use similar diversifier
/// and public key structures.
pub(crate) type Data = [u8; 43];
