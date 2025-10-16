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
    pub fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Regtest => 0x6F,
        }
    }
}
