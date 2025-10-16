/// src/utils/address_types.rs

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressType {
    P2PKH, // Pay-to-Public-Key-Hash (legacy)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    /// Returns the version byte for the network in P2PKH format.
    ///
    /// - `Network::Mainnet`: 0x00
    /// - `Network::Testnet` and `Network::Regtest`: 0x6F
    pub fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Regtest => 0x6F,
        }
    }

    /// Returns the version byte for the network in WIF format.
    ///
    /// - `Network::Mainnet`: 0x80
    /// - `Network::Testnet` and `Network::Regtest`: 0xEF
    pub fn wif_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet | Network::Regtest => 0xEF,
        }
    }
}
