
use mbedtls::hash::{Md, Type as MdType};
use std::result::{Result as StdResult};
use std::cell::Cell;

type Result<T> = StdResult<T, mbedtls::Error>;

struct LmsPrivateKey {
    q: Cell<u32>,
}

struct LmsPublicKey {

}

impl LmsPrivateKey {
    fn new(seed: &[u8]) -> Result<LmsPrivateKey> {

        let sha256 = Md::new(MdType::Sha256);
        Ok(LmsPrivateKey {
            q: Cell::new(0),
        })
    }

    fn sign(message: &[u8]) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn public_key(&self) -> Result<LmsPublicKey> {
        Ok(LmsPublicKey {})
    }
}

impl LmsPublicKey {

    fn verify(message: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(false)
    }

}

fn main() {
    println!("Hello, world!");
}
