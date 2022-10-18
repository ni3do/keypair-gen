use eth_keypair::EthereumPrivateKey;
mod crypto_util;
mod eth_address;
mod eth_keypair;
mod util;

fn main() {
    let pk = EthereumPrivateKey::gen();
    let address = pk.to_address();
    println!("Address:      {}", address);
    println!("Private key:  {}", pk);
}
