
use mbedtls::hash::{Md, Type as MdType};
use mbedtls::rng::{Random};
use std::result::{Result as StdResult};
use std::cell::Cell;

type Result<T> = StdResult<T, mbedtls::Error>;

/* Parameters */

const W : usize = 8;
const N : usize = 32; // SHA-256
const LS : usize = 0;
const P : usize = 34;
const Q_LEN : usize = 4;
const OTS_SIGNATURE_LENGTH : usize = 1124; // Table 1

/* XDR identifiers */
const LMOTS_SHA256_N32_W8 : usize = 4;

struct LmOtsPrivateKey {

}

impl LmOtsPrivateKey {
    fn new(rng: &impl Random, I: &[u8], q: u32) -> Result<LmOtsPrivateKey> {
        Ok(LmOtsPrivateKey {})
    }

}


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
    let mut entropy = mbedtls::rng::OsEntropy::new();
    let mut rng = mbedtls::rng::CtrDrbg::new(&mut entropy, None).unwrap();

    let I = vec![0; 16];
    let q = 1;
    let lmots = LmOtsPrivateKey::new(&rng, &I, q);
}
