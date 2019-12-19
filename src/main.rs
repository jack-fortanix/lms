
use mbedtls::hash::{Md, Type as MdType};
use mbedtls::rng::{Random};
use std::result::{Result as StdResult};
use std::convert::TryInto;
use std::cell::Cell;

type Result<T> = StdResult<T, mbedtls::Error>;

/* Parameters */

const H : usize = 5; // FIXME!
const H_POW : u32 = (1 << H) as u32;
const W : usize = 8;
const N : usize = 32; // SHA-256
const LS : usize = 0;
const P : usize = 34;
const Q_LEN : usize = 4;
const I_LEN : usize = 16;

const OTS_SIGNATURE_LENGTH : usize = 1124; // Table 1

const D_PBLC : u16 = 0x8080;
const D_MESG : u16 = 0x8181;
const D_LEAF : u16 = 0x8282;
const D_INTR : u16 = 0x8383;

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

fn new_ots(seed: &[u8], I: &[u8], q: u32) -> Result<(LmOtsPrivateKey,LmOtsPublicKey)> {
    assert_eq!(seed.len(), N);
    assert_eq!(I.len(), I_LEN);
    //assert!(q > 0);

    let mut sk = vec![0; 4 + I_LEN + Q_LEN + N*P];
    sk[0..4].copy_from_slice(&LMOTS_SHA256_N32_W8.to_be_bytes());
    sk[4..20].copy_from_slice(I);
    sk[20..24].copy_from_slice(&q.to_be_bytes());

    let mut pk = vec![0u8; 24+N];
    pk[0..24].copy_from_slice(&sk[0..24]); // header is the same

    let iq = sk[4..24].to_vec();

    let mut k_sha256 = Md::new(MdType::Sha256)?;
    k_sha256.update(&iq)?;
    k_sha256.update(&D_PBLC.to_be_bytes())?;

    let mut digest = vec![0; N];
    // This loop can execute in parallel:
    for i in 0..P {
        let mut sha256 = Md::new(MdType::Sha256)?;
        sha256.update(&iq)?;
        sha256.update(&(i as u16).to_be_bytes())?;
        sha256.update(&[0xFF]);
        sha256.update(seed);
        sha256.finish(&mut digest);
        sk[24+i*N..24+i*N+N].copy_from_slice(&digest);

        // This loop can execute in parallel or with SIMD:
        for j in 0..255 {
            let mut sha256 = Md::new(MdType::Sha256)?;
            sha256.update(&iq)?;
            sha256.update(&(i as u16).to_be_bytes())?;
            sha256.update(&(j as u8).to_be_bytes())?;
            sha256.update(&digest)?;
            sha256.finish(&mut digest).unwrap();
        }
        // y[i] is tmp which is fed into computation of K
        k_sha256.update(&digest)?;
    }

    k_sha256.finish(&mut pk[24..]).unwrap();
    Ok((LmOtsPrivateKey { sk }, LmOtsPublicKey { pk }))
}

fn ots_sign(sk: &LmOtsPrivateKey, message: &[u8], rnd: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(rnd.len(), N);

    let iq = &sk.sk[4..24]; // I || q

    let q = hash_to_q(message, rnd, iq)?;

    let mut sig = vec![0u8; OTS_SIGNATURE_LENGTH];
    sig[0..4].copy_from_slice(&sk.sk[0..4]); // type
    sig[4..4+N].copy_from_slice(rnd); // C

    for i in 0..P {
        let a = coef(&q, i);
        let mut t = sk.sk[24+N*i..24+N*i+N].to_vec();
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

fn ots_verify(pk: &LmOtsPublicKey, message: &[u8], sig: &[u8]) -> Result<bool> {
    if sig.len() != OTS_SIGNATURE_LENGTH {
        return Ok(false);
    }

    if u32::from_be_bytes(sig[0..4].try_into().expect("4 bytes")) != LMOTS_SHA256_N32_W8 {
        return Ok(false);
    }

    let iq = &pk.pk[4..24]; // I || q
    let k = &pk.pk[24..24+N]; // K

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
    return Ok(kc == k);
}

struct LmsPrivateKey {
    I: Vec<u8>,
    K: Vec<u8>,
    q: Cell<u32>,
    pk: Vec<u8>,
}

struct LmsPublicKey {
    pk: Vec<u8>,
}

impl LmsPrivateKey {
    fn new(seed: &[u8]) -> Result<LmsPrivateKey> {
        assert_eq!(seed.len(), I_LEN + N);

        let I = seed[0..I_LEN].to_vec();
        let seed = seed[I_LEN..].to_vec();

        let mut ots_pk = Vec::with_capacity(H_POW as usize);

        for q in 0..H_POW {
            // The sk can be rederived from the seed when needed
            let (_sk,pk) = new_ots(&seed, &I, q)?;
            let pk = pk.pk[24..].to_vec(); // FIXME just don't add header to pk
            ots_pk.push(pk);
        }

        // See RFC 8554 Appendix C
        // FIXME do each key without storing it !
        /*

     if r >= 2^h:
          H(I||u32str(r)||u16str(D_LEAF)||OTS_PUB_HASH[r-2^h])
     else
          H(I||u32str(r)||u16str(D_INTR)||T[2*r]||T[2*r+1])
         */
        let mut stack : std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::with_capacity(30); // fixme bogus capacity ...
        for i in 0..H_POW {
            let mut r : u32 = i + H_POW; // ???
            let mut t = vec![0u8; N];
            let mut t_hash = Md::new(MdType::Sha256)?;
            t_hash.update(&I);
            t_hash.update(&r.to_be_bytes());
            t_hash.update(&D_LEAF.to_be_bytes());
            t_hash.update(&ots_pk[i as usize]);
            t_hash.finish(&mut t);

            let mut j = i;
            while j % 2 == 1 {
                r = (r - 1) / 2;
                j = (j - 1) / 2;
                let ls = stack.pop_front().expect("Stack not empty");
                let mut l_hash = Md::new(MdType::Sha256)?;
                l_hash.update(&I);
                l_hash.update(&r.to_be_bytes());
                l_hash.update(&D_INTR.to_be_bytes());
                l_hash.update(&ls);
                l_hash.update(&t);
                l_hash.finish(&mut t);
            }

            stack.push_back(t);
        }

        Ok(LmsPrivateKey {
            I: I,
            K: seed,
            q: Cell::new(0),
            pk: vec![], // FIXME
        })
    }

    fn sign(message: &[u8]) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn public_key(&self) -> Result<LmsPublicKey> {
        Ok(LmsPublicKey { pk: vec![] })
    }
}

impl LmsPublicKey {

    fn from_sk(sk: LmsPrivateKey) -> Result<LmsPublicKey> {
        Ok(LmsPublicKey { pk: sk.pk })
    }

    fn verify(message: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(false)
    }

}

#[test]
fn ots_test() {
    let I = vec![0; I_LEN];
    let q = 1;

    let ots_seed = vec![0; N];
    let (sk,pk) = new_ots(&ots_seed, &I, q).unwrap();

    let C = vec![0; 32];

    let msg = vec![1,2,3];

    let sig = ots_sign(&sk, &msg, &C).unwrap();

    assert!(ots_verify(&pk, &msg, &sig).unwrap());

    let wrong = vec![2,2,3];
    assert!(ots_verify(&pk, &wrong, &sig).unwrap() == false);
}

fn main() {
    //let mut entropy = mbedtls::rng::OsEntropy::new();
    //let mut rng = mbedtls::rng::CtrDrbg::new(&mut entropy, None).unwrap();

    let ots_seed = vec![0; N+16];
    let sk = LmsPrivateKey::new(&ots_seed).unwrap();

    println!("ok");
}
