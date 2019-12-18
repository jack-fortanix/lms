
use mbedtls::hash::{Md, Type as MdType};
use mbedtls::rng::{Random};
use std::result::{Result as StdResult};
use std::convert::TryInto;
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

fn coef(v: &[u8], i: usize) -> u8 {
    v[i]
}

fn add_checksum(v : &mut Vec<u8>) {
    let mut sum : u16 = 0;
    for i in 0..(N*8)/W {
        sum += 255u16 - coef(v, i) as u16;
    }

    v.push((sum >> 8) as u8);
    v.push((sum & 0xFF) as u8);
}

fn hash_to_q(message: &[u8], rnd: &[u8], iq: &[u8]) -> Result<Vec<u8>> {
    let mut q = vec![0; N];
    let mut q_hash = Md::new(MdType::Sha256)?;
    q_hash.update(iq)?;
    q_hash.update(&D_MESG.to_be_bytes())?;
    q_hash.update(rnd)?;
    q_hash.update(message)?;
    q_hash.finish(&mut q)?;
    add_checksum(&mut q);
    Ok(q)
}

#[derive(Clone, Debug)]
struct LmOtsPrivateKey {
    sk: Vec<u8>
}

#[derive(Clone, Debug)]
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

        // hack for mbedtls sigh 
        rng.random(&mut sk[24..24+100])?;
        rng.random(&mut sk[24+100..])?;

        Ok(LmOtsPrivateKey { sk })
    }

    fn sign(&self, message: &[u8], rnd: &[u8]) -> Result<Vec<u8>> {
        assert_eq!(rnd.len(), N);

        let iq = &self.sk[4..24]; // I || q

        let q = hash_to_q(message, rnd, iq)?;

        let mut sig = vec![0u8; OTS_SIGNATURE_LENGTH];
        sig[0..4].copy_from_slice(&self.sk[0..4]); // type
        sig[4..4+N].copy_from_slice(rnd); // C

        for i in 0..P {
            let a = coef(&q, i);
            let mut t = self.sk[24+N*i..24+N*i+N].to_vec();
            for j in 0..a {
                let mut sha256 = Md::new(MdType::Sha256)?;
                sha256.update(iq)?;
                sha256.update(&(i as u16).to_be_bytes())?;
                sha256.update(&(j as u8).to_be_bytes())?;
                sha256.update(&t)?;
                sha256.finish(&mut t)?;
            }

            sig[4+N+N*i..4+N+N*i+N].copy_from_slice(&t);
        }

        Ok(sig)
    }
}

impl LmOtsPublicKey {
    fn from_sk(sk: &LmOtsPrivateKey) -> Result<LmOtsPublicKey> {

        // I and q are contiguous both in sk and in hash input
        let iq = &sk.sk[4..24];

        let mut k_sha256 = Md::new(MdType::Sha256)?;
        k_sha256.update(iq)?;
        k_sha256.update(&D_PBLC.to_be_bytes())?;

        println!("sk = {:?}", sk.sk);
        for i in 0..P {
            //println!("i={}", i);
            let mut t = sk.sk[24+N*i..24+N*i+N].to_vec();
            //println!("t={:?}", t);
            assert_eq!(t.len(), N);
            for j in 0..255 {
                let mut sha256 = Md::new(MdType::Sha256)?;
                sha256.update(iq)?;
                sha256.update(&(i as u16).to_be_bytes())?;
                sha256.update(&(j as u8).to_be_bytes())?;
                sha256.update(&t)?;
                sha256.finish(&mut t).unwrap();
            }
            // y[i] is tmp which is fed into computation of K
            k_sha256.update(&t)?;
        }

        let mut pk = vec![0u8; 24+N];
        pk[0..24].copy_from_slice(&sk.sk[0..24]); // header is the same
        k_sha256.finish(&mut pk[24..]).unwrap();
        Ok(LmOtsPublicKey { pk })
    }

    fn verify(&self, message: &[u8], sig: &[u8]) -> Result<bool> {
        if sig.len() != OTS_SIGNATURE_LENGTH {
            println!("wrong len");
            return Ok(false);
        }

        if u32::from_be_bytes(sig[0..4].try_into().expect("4 bytes")) != LMOTS_SHA256_N32_W8 {
            println!("bad type??");
            return Ok(false);
        }

        let iq = &self.pk[4..24]; // I || q
        let k = &self.pk[24..24+N]; // K

        let q = hash_to_q(message, &sig[4..4+N], iq)?;

        let mut k_sha256 = Md::new(MdType::Sha256)?;
        k_sha256.update(iq)?;
        k_sha256.update(&D_PBLC.to_be_bytes())?;

        for i in 0..P {
            let a = coef(&q, i);
            let mut t = sig[4+N+N*i..4+N+N*i+N].to_vec();
            for j in a..255 {
                let mut sha256 = Md::new(MdType::Sha256)?;
                sha256.update(iq)?;
                sha256.update(&(i as u16).to_be_bytes())?;
                sha256.update(&(j as u8).to_be_bytes())?;
                sha256.update(&t)?;
                sha256.finish(&mut t)?;
            }
            k_sha256.update(&t)?;
        }

        let mut kc = vec![0u8; N];
        k_sha256.finish(&mut kc)?;


        println!("kc = {:?}", kc);
        println!("k = {:?}", k);
        if kc == k {
            return Ok(true);
        }
        else {
            return Ok(false);
        }
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
    let sk = LmOtsPrivateKey::new(&mut rng, &I, q).unwrap();
    println!("{:?}", sk);
    let pk = LmOtsPublicKey::from_sk(&sk).unwrap();

    let C = vec![0; 32];
    
    let msg = vec![1,2,3];

    let sig = sk.sign(&msg, &C).unwrap();

    assert!(pk.verify(&msg, &sig).unwrap());
}
