
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

const D_PBLC : u16 = 0x8080;
const D_MESG : u16 = 0x8181;

/* XDR identifiers */
const LMOTS_SHA256_N32_W8 : u32 = 4;

/*
fn checksum(s: &[u8]) -> Vec<u8> {
    let mut sum : u16 = 0;
}
*/

struct LmOtsPrivateKey {
    sk: Vec<u8>
}

struct LmOtsPublicKey {
    pk: Vec<u8>
}

impl LmOtsPrivateKey {
    fn new(rng: &mut impl Random, I: &[u8], q: u32) -> Result<LmOtsPrivateKey> {
        // TODO instead derive it via a seed as in Appendix A
        assert_eq!(I.len(), 16);
        assert!(q > 0);

        let ots_privkey_len = 4 + 16 + 4 + N*P;
        let mut sk = vec![0; ots_privkey_len];
        sk[0..4].copy_from_slice(&LMOTS_SHA256_N32_W8.to_be_bytes());
        sk[4..20].copy_from_slice(I);
        sk[20..24].copy_from_slice(&q.to_be_bytes());
        rng.random(&mut sk[24..]);

        Ok(LmOtsPrivateKey { sk })
    }
}

impl LmOtsPublicKey {
    fn from_sk(sk: &LmOtsPrivateKey) -> Result<LmOtsPublicKey> {

        // I and q are contiguous both in sk and in hash input
        let iq = &sk.sk[4..24];

        let mut k_sha256 = Md::new(MdType::Sha256)?;
        k_sha256.update(iq);
        k_sha256.update(&D_PBLC.to_be_bytes());

        for i in 0..P {
            let mut t = sk.sk[24+N*i..24+(N+1)*i].to_vec();
            for j in 0..255 {
                let mut sha256 = Md::new(MdType::Sha256)?;
                sha256.update(iq)?;
                sha256.update(&(i as u16).to_be_bytes())?;
                sha256.update(&(j as u8).to_be_bytes())?;
                sha256.update(&t)?;
                sha256.finish(&mut t)?;
            }
            // y[i] is tmp which is fed into computation of K
            k_sha256.update(&t)?;
        }

        let mut pk = vec![0u8; 24+N];
        pk.copy_from_slice(&sk.sk[0..24]); // header is the same
        k_sha256.finish(&mut pk[24..])?;
        Ok(LmOtsPublicKey { pk })
    }
}

/*
struct LmsPrivateKey {
    q: Cell<u32>,
}

struct LmsPublicKey {

}

impl LmsPrivateKey {
    fn new(seed: &[u8]) -> Result<LmsPrivateKey> {

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
 */

fn main() {
    let mut entropy = mbedtls::rng::OsEntropy::new();
    let mut rng = mbedtls::rng::CtrDrbg::new(&mut entropy, None).unwrap();

    let I = vec![0; 16];
    let q = 1;
    let lmots = LmOtsPrivateKey::new(&mut rng, &I, q);
}
