
use mbedtls::hash::{Md, Type as MdType};
use mbedtls::rng::{Random};
use std::result::{Result as StdResult};
use std::collections::BTreeMap;
use std::convert::TryInto;

use rustc_serialize::hex::ToHex;// remove just for debug

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
const M : usize = 32; // SHA-256

const OTS_SIGNATURE_LENGTH : usize = 1124; // Table 1

const D_PBLC : u16 = 0x8080;
const D_MESG : u16 = 0x8181;
const D_LEAF : u16 = 0x8282;
const D_INTR : u16 = 0x8383;

/* XDR identifiers */
const LMOTS_SHA256_N32_W1 : u32 = 1;
const LMOTS_SHA256_N32_W2 : u32 = 2;
const LMOTS_SHA256_N32_W4 : u32 = 3;
const LMOTS_SHA256_N32_W8 : u32 = 4;

const LMS_SHA256_N32_H5 : u32 = 5;
const LMS_SHA256_N32_H10 : u32 = 6;
const LMS_SHA256_N32_H15 : u32 = 7;
const LMS_SHA256_N32_H20 : u32 = 8;
const LMS_SHA256_N32_H25 : u32 = 9;

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

// ???
fn hash_to_qx(message: &[u8], rnd: &[u8], i: &[u8], q: u32) -> Result<Vec<u8>> {
    let mut r = vec![0; N];
    let mut r_hash = Md::new(MdType::Sha256)?;

    //println!("Input = {}{:08X}{:04X}{}{}", i.to_hex(), q, D_MESG, rnd.to_hex(), message.to_hex());
    r_hash.update(i)?;
    r_hash.update(&q.to_be_bytes());
    r_hash.update(&D_MESG.to_be_bytes())?;
    r_hash.update(rnd)?;
    r_hash.update(message)?;
    r_hash.finish(&mut r)?;
    //println!("Output = {}", r.to_hex());
    add_checksum(&mut r);
    Ok(r)
}

fn lms_hash(mut out: &mut [u8], inputs: Vec<&[u8]>) -> Result<()> {
    let mut sha256 = Md::new(MdType::Sha256)?;

    let mut hinput = "".to_owned();

    for input in inputs {
        hinput += &input.to_hex();
        sha256.update(input);
    }

    sha256.finish(&mut out)?;
    //println!("Input {}", hinput);
    //println!("Output {}", out.to_hex());

    Ok(())
}

#[derive(Clone, Debug)]
struct LmOtsPrivateKey {
    sk: Vec<u8>
}

#[derive(Clone, Debug)]
struct LmOtsPublicKey {
    pk: Vec<u8>
}

fn compute_ots_pk(sk: &LmOtsPrivateKey) -> Result<LmOtsPublicKey> {
    let iq = sk.sk[4..24].to_vec();

    let mut k_sha256 = Md::new(MdType::Sha256)?;
    k_sha256.update(&iq)?;
    k_sha256.update(&D_PBLC.to_be_bytes())?;

    for i in 0..P {
        let mut digest = sk.sk[24+i*N..24+i*N+N].to_vec();

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

    let mut pk = vec![0u8; 24+N];
    pk[0..24].copy_from_slice(&sk.sk[0..24]); // header is the same
    k_sha256.finish(&mut pk[24..]).unwrap();
    Ok(LmOtsPublicKey { pk })
}

fn new_ots_sk(seed: &[u8], I: &[u8], q: u32) -> Result<LmOtsPrivateKey> {
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

    let mut digest = vec![0; N];

    // This loop can execute in parallel:
    for i in 0..P {
        lms_hash(&mut digest, vec![&iq, &(i as u16).to_be_bytes(), &[0xFF], seed])?;
        sk[24+i*N..24+i*N+N].copy_from_slice(&digest);
    }

    let sk = LmOtsPrivateKey { sk };
    Ok(sk)
}

fn new_ots(seed: &[u8], I: &[u8], q: u32) -> Result<(LmOtsPrivateKey,LmOtsPublicKey)> {
    let sk = new_ots_sk(seed, I, q)?;
    let pk = compute_ots_pk(&sk)?;
    Ok((sk,pk))
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

fn algorithm_4b(id: &[u8], q: u32, message: &[u8], sig: &[u8]) -> Result<Vec<u8>> {
    if sig.len() != OTS_SIGNATURE_LENGTH {
        panic!("wut");
        return Ok(vec![]);
    }

    if u32::from_be_bytes(sig[0..4].try_into().expect("4 bytes")) != LMOTS_SHA256_N32_W8 {
        panic!("wut x2");
        return Ok(vec![]);
    }

    let Q = hash_to_qx(message, &sig[4..4+N], id, q)?;

    let mut k_sha256 = Md::new(MdType::Sha256)?;
    k_sha256.update(id)?;
    k_sha256.update(&q.to_be_bytes())?;
    k_sha256.update(&D_PBLC.to_be_bytes())?;

    for i in 0..P {
        let a = coef(&Q, i);
        let mut t = sig[4+N+N*i..4+N+N*i+N].to_vec();
        for j in a..255 {
            let mut sha256 = Md::new(MdType::Sha256)?;

            //println!("Input = {}{:08X}{:04X}{:02X}{}", id.to_hex(), q, i, j, t.to_hex());
            sha256.update(id)?;
            sha256.update(&q.to_be_bytes())?;
            sha256.update(&(i as u16).to_be_bytes())?;
            sha256.update(&(j as u8).to_be_bytes())?;
            sha256.update(&t)?;
            sha256.finish(&mut t)?;
            //println!("Output = {}", t.to_hex());
        }
        k_sha256.update(&t)?;
    }

    let mut kc = vec![0u8; N];
    k_sha256.finish(&mut kc)?;
    //println!("Kc = {}", kc.to_hex());
    return Ok(kc);
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
    pk_type: u32,
    q: u32,
    pk: Vec<u8>,
    Ts: BTreeMap<u32, Vec<u8>>,
}

struct LmsPublicKey {
    pk: Vec<u8>,
}

impl LmsPrivateKey {
    fn new(seed: &[u8]) -> Result<LmsPrivateKey> {
        assert_eq!(seed.len(), I_LEN + N);

        let I = seed[0..I_LEN].to_vec();
        let seed = seed[I_LEN..].to_vec();

        let pk_type = LMS_SHA256_N32_H5; // fixme

        // Instead let mut Ts = vec[H_POW; vec![0; N]]; ??
        let mut Ts = BTreeMap::new();

        // See RFC 8554 Appendix C
        let mut stack : std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::with_capacity(H - 1);

        for i in 0..H_POW {
            let (_sk,pk) = new_ots(&seed, &I, i)?;

            let mut r : u32 = i + H_POW; // ???
            let mut t = vec![0u8; N];
            let mut t_hash = Md::new(MdType::Sha256)?;
            t_hash.update(&I);
            t_hash.update(&r.to_be_bytes());
            t_hash.update(&D_LEAF.to_be_bytes());
            println!("LEAF {} = {}", r, pk.pk[24..].to_hex());
            t_hash.update(&pk.pk[24..]); // fixme don't add header here
            t_hash.finish(&mut t);

            println!("T[{}] = {}", r, t.to_hex());
            assert!(!Ts.contains_key(&r));
            Ts.insert(r, t.to_vec());

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

                println!("KeyGen node {} from {}, {}", r, ls.to_hex(),t.to_hex());
                //println!("Intr {} = {}", r, t.to_hex());

                l_hash.update(&t);
                l_hash.finish(&mut t);
                assert!(!Ts.contains_key(&r));
                Ts.insert(r, t.to_vec());
                println!("T[{}] = {}", r, t.to_hex());

            }

            stack.push_front(t);
        }

        assert_eq!(stack.len(), 1);

        // FIXME add types and I
        let mut pk_t1 = stack.pop_front().expect("Stack not empty");

        let mut pk = vec![];
        pk.extend(pk_type.to_be_bytes().iter());
        pk.extend(LMOTS_SHA256_N32_W8.to_be_bytes().iter());
        pk.extend(I.clone());
        pk.extend(pk_t1);

        Ok(LmsPrivateKey {
            I: I,
            K: seed,
            q: 1,
            pk: pk,
            pk_type: pk_type,
            Ts: Ts,
        })
    }

    fn sign(&mut self, message: &[u8], rnd: &[u8]) -> Result<Vec<u8>> {
        assert_eq!(rnd.len(), N);
        let q = self.q;
        self.q += 1;
        let sk = new_ots_sk(&self.K, &self.I, q)?;

        let mut ots_sig = ots_sign(&sk, message, rnd)?;

        /*
        u32str(q) || lmots_signature || u32str(type) || path[0] || path[1] || path[2] || ... || path[h-1]
        */
        let mut sig = vec![];
        sig.extend(q.to_be_bytes().iter());
        sig.append(&mut ots_sig);
        sig.extend(self.pk_type.to_be_bytes().iter());

        let mut r = H_POW + q;
        for i in 0..H {
            let idx = (r >> i) ^ 1;
            assert!(self.Ts.contains_key(&idx));
            println!("path {} = {}", idx, self.Ts[&idx].to_hex());
            sig.extend(self.Ts[&idx].to_owned());
        }

        Ok(sig)
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn public_key(&self) -> Result<LmsPublicKey> {
        Ok(LmsPublicKey { pk: self.pk.clone() })
    }
}

impl LmsPublicKey {

    fn from_sk(sk: LmsPrivateKey) -> Result<LmsPublicKey> {
        Ok(LmsPublicKey { pk: sk.pk })
    }

    fn from_bytes(pk: &[u8]) -> Result<LmsPublicKey> {
        Ok(LmsPublicKey { pk: pk.to_owned() })
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        // pubtype + ots_typecode + I + K
        if self.pk.len() != (4 + 4 + 16 + 32) {
            println!("bad pk {}", self.pk.len());
            return Ok(false);
        }

        let pk_type = u32::from_be_bytes(self.pk[0..4].try_into().expect("4 bytes"));

        let h = match pk_type {
            LMS_SHA256_N32_H5 => 5,
            LMS_SHA256_N32_H10 => 10,
            LMS_SHA256_N32_H15 => 15,
            LMS_SHA256_N32_H20 => 20,
            LMS_SHA256_N32_H25 => 25,
            _ => return Ok(false)
        };

        let ots_type = u32::from_be_bytes(self.pk[4..8].try_into().expect("4 bytes"));

        if ots_type != LMOTS_SHA256_N32_W8 {
            println!("bad ots");
            return Ok(false); // Only support W=8
        }

        let expected_sig_len = 12 + N*(P+1) + M*h;
        if signature.len() != expected_sig_len { // ????
            println!("bad sig len? {} vs {}", signature.len(), expected_sig_len);
            return Ok(false);
        }

        let sig_pk_type = u32::from_be_bytes(signature[8+N*(P+1)..12+N*(P+1)].try_into().expect("4 bytes"));

        if pk_type != sig_pk_type {
            println!("signature and pk types don't match (??)");
            return Ok(false);
        }

        let q = u32::from_be_bytes(signature[0..4].try_into().expect("4 bytes"));
        if q >= (1u32 << h) {
            println!("q out of range");
            return Ok(false);
        }

        if u32::from_be_bytes(signature[4..8].try_into().expect("4 bytes")) != LMOTS_SHA256_N32_W8 {
            println!("wrong type");
            return Ok(false);
        }

        // Algorithm 6a
        let lmots_signature = &signature[4..8+N*(P+1)];

        let paths = &signature[12+N*(P+1)..];

        /*
        3. Kc = candidate public key computed by applying Algorithm 4b
        to the signature lmots_signature, the message, and the
        identifiers I, q
         */
        let I = self.pk[8..8+I_LEN].to_vec(); // I
        assert_eq!(I.len(), I_LEN);

        let Kc = algorithm_4b(&I, q, message, lmots_signature)?;
        assert!(Kc.len() == M);
        println!("Kc = {}", Kc.to_hex());

        let T1 = self.pk[24..].to_vec();
        println!("pk = {}", self.pk.to_hex());
        println!("T1 = {}", T1.to_hex());

        let mut Tc = vec![0; N];
/*
        node_num = 2^h + q
        tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
        i = 0
        while (node_num > 1) {
          if (node_num is odd):
            tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||path[i]||tmp)
          else:
            tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||tmp||path[i])
          node_num = node_num/2
          i = i + 1
        }
        Tc = tmp
         */
        let mut node_num : u32 = q + H_POW;
        lms_hash(&mut Tc, vec![&I, &node_num.to_be_bytes(), &D_LEAF.to_be_bytes(), &Kc]);

        let mut i = 0;

        let mut tmp = vec![0; N];

        while node_num > 1 {
            let odd = if node_num % 2 == 1 { true } else { false };

            node_num /= 2;

            let mut t_hash = Md::new(MdType::Sha256)?;

            t_hash.update(&I);
            t_hash.update(&node_num.to_be_bytes());
            t_hash.update(&D_INTR.to_be_bytes());

            if odd {
                println!("Path {} {}", i, "Tc");
                println!("Computing node {} from {} {}", node_num, &paths[N*i..N*(i+1)].to_hex(), Tc.to_hex());
                t_hash.update(&paths[N*i..N*(i+1)]);
                t_hash.update(&Tc);
            } else {
                println!("Path {} {}", "Tc", i);
                println!("Computing node {} from {} {}", node_num, Tc.to_hex(), &paths[N*i..N*(i+1)].to_hex());
                t_hash.update(&Tc);
                t_hash.update(&paths[N*i..N*(i+1)]);
            }
            t_hash.finish(&mut Tc);
            println!("Output = {}", Tc.to_hex());

            i = i + 1;
        }

        println!("TC = {}", Tc.to_hex());
        Ok(T1 == Tc)
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

/*
LMS-OTS signature is:

      u32str(type) || C || y[0] || ... || y[p-1]

LMS signature is:

       u32str(q) || lmots_signature || u32str(type) ||
                 path[0] || path[1] || path[2] || ... || path[h-1]

HSS signature is

     Return u32str(L-1) || signed_pub_key[0] || ... || signed_pub_key[L-2] || sig[L-1]


   --------------------------------------------
   HSS signature
   Nspk        00000001
   sig[0]:
   --------------------------------------------
   LMS signature
   q           00000005
   --------------------------------------------
   LMOTS signature
   LMOTS type  00000004                         # LMOTS_SHA256_N32_W8
   C           d32b56671d7eb98833c49b433c272586
               bc4a1c8a8970528ffa04b966f9426eb9
   y[0]        965a25bfd37f196b9073f3d4a232feb6
               9128ec45146f86292f9dff9610a7bf95
   y[1]        a64c7f60f6261a62043f86c70324b770
               7f5b4a8a6e19c114c7be866d488778a0
   y[2]        e05fd5c6509a6e61d559cf1a77a970de
               927d60c70d3de31a7fa0100994e162a2
   y[3]        582e8ff1b10cd99d4e8e413ef469559f
               7d7ed12c838342f9b9c96b83a4943d16
   y[4]        81d84b15357ff48ca579f19f5e71f184
               66f2bbef4bf660c2518eb20de2f66e3b
   y[5]        14784269d7d876f5d35d3fbfc7039a46
               2c716bb9f6891a7f41ad133e9e1f6d95
   y[6]        60b960e7777c52f060492f2d7c660e14
               71e07e72655562035abc9a701b473ecb
   y[7]        c3943c6b9c4f2405a3cb8bf8a691ca51
               d3f6ad2f428bab6f3a30f55dd9625563
   y[8]        f0a75ee390e385e3ae0b906961ecf41a
               e073a0590c2eb6204f44831c26dd768c
   y[9]        35b167b28ce8dc988a3748255230cef9
               9ebf14e730632f27414489808afab1d1
   y[10]       e783ed04516de012498682212b078105
               79b250365941bcc98142da13609e9768
   y[11]       aaf65de7620dabec29eb82a17fde35af
               15ad238c73f81bdb8dec2fc0e7f93270
   y[12]       1099762b37f43c4a3c20010a3d72e2f6
               06be108d310e639f09ce7286800d9ef8
   y[13]       a1a40281cc5a7ea98d2adc7c7400c2fe
               5a101552df4e3cccfd0cbf2ddf5dc677
   y[14]       9cbbc68fee0c3efe4ec22b83a2caa3e4
               8e0809a0a750b73ccdcf3c79e6580c15
   y[15]       4f8a58f7f24335eec5c5eb5e0cf01dcf
               4439424095fceb077f66ded5bec73b27
   y[16]       c5b9f64a2a9af2f07c05e99e5cf80f00
               252e39db32f6c19674f190c9fbc506d8
   y[17]       26857713afd2ca6bb85cd8c107347552
               f30575a5417816ab4db3f603f2df56fb
   y[18]       c413e7d0acd8bdd81352b2471fc1bc4f
               1ef296fea1220403466b1afe78b94f7e
   y[19]       cf7cc62fb92be14f18c2192384ebceaf
               8801afdf947f698ce9c6ceb696ed70e9
   y[20]       e87b0144417e8d7baf25eb5f70f09f01
               6fc925b4db048ab8d8cb2a661ce3b57a
   y[21]       da67571f5dd546fc22cb1f97e0ebd1a6
               5926b1234fd04f171cf469c76b884cf3
   y[22]       115cce6f792cc84e36da58960c5f1d76
               0f32c12faef477e94c92eb75625b6a37
   y[23]       1efc72d60ca5e908b3a7dd69fef02491
               50e3eebdfed39cbdc3ce9704882a2072
   y[24]       c75e13527b7a581a556168783dc1e975
               45e31865ddc46b3c957835da252bb732
   y[25]       8d3ee2062445dfb85ef8c35f8e1f3371
               af34023cef626e0af1e0bc017351aae2
   y[26]       ab8f5c612ead0b729a1d059d02bfe18e
               fa971b7300e882360a93b025ff97e9e0
   y[27]       eec0f3f3f13039a17f88b0cf808f4884
               31606cb13f9241f40f44e537d302c64a
   y[28]       4f1f4ab949b9feefadcb71ab50ef27d6
               d6ca8510f150c85fb525bf25703df720
   y[29]       9b6066f09c37280d59128d2f0f637c7d
               7d7fad4ed1c1ea04e628d221e3d8db77
   y[30]       b7c878c9411cafc5071a34a00f4cf077
               38912753dfce48f07576f0d4f94f42c6
   y[31]       d76f7ce973e9367095ba7e9a3649b7f4
               61d9f9ac1332a4d1044c96aefee67676
   y[32]       401b64457c54d65fef6500c59cdfb69a
               f7b6dddfcb0f086278dd8ad0686078df
   y[33]       b0f3f79cd893d314168648499898fbc0
               ced5f95b74e8ff14d735cdea968bee74
   --------------------------------------------
   LMS type    00000005                         # LM_SHA256_M32_H5
   path[0]     d8b8112f9200a5e50c4a262165bd342c
               d800b8496810bc716277435ac376728d
   path[1]     129ac6eda839a6f357b5a04387c5ce97
               382a78f2a4372917eefcbf93f63bb591
   path[2]     12f5dbe400bd49e4501e859f885bf073
               6e90a509b30a26bfac8c17b5991c157e
   path[3]     b5971115aa39efd8d564a6b90282c316
               8af2d30ef89d51bf14654510a12b8a14
   path[4]     4cca1848cf7da59cc2b3d9d0692dd2a2
               0ba3863480e25b1b85ee860c62bf5136
   --------------------------------------------

   LMS public key
   LMS type    00000005                         # LM_SHA256_M32_H5
   LMOTS type  00000004                         # LMOTS_SHA256_N32_W8
   I           d2f14ff6346af964569f7d6cb880a1b6
   K           6c5004917da6eafe4d9ef6c6407b3db0
               e5485b122d9ebe15cda93cfec582d7ab
   --------------------------------------------
   final_signature:
   --------------------------------------------
   LMS signature
   q           0000000a
   --------------------------------------------
   LMOTS signature
   LMOTS type  00000004                         # LMOTS_SHA256_N32_W8
   C           0703c491e7558b35011ece3592eaa5da
               4d918786771233e8353bc4f62323185c
   y[0]        95cae05b899e35dffd71705470620998
               8ebfdf6e37960bb5c38d7657e8bffeef
   y[1]        9bc042da4b4525650485c66d0ce19b31
               7587c6ba4bffcc428e25d08931e72dfb
   y[2]        6a120c5612344258b85efdb7db1db9e1
               865a73caf96557eb39ed3e3f426933ac
   y[3]        9eeddb03a1d2374af7bf771855774562
               37f9de2d60113c23f846df26fa942008
   y[4]        a698994c0827d90e86d43e0df7f4bfcd
               b09b86a373b98288b7094ad81a0185ac
   y[5]        100e4f2c5fc38c003c1ab6fea479eb2f
               5ebe48f584d7159b8ada03586e65ad9c
   y[6]        969f6aecbfe44cf356888a7b15a3ff07
               4f771760b26f9c04884ee1faa329fbf4
   y[7]        e61af23aee7fa5d4d9a5dfcf43c4c26c
               e8aea2ce8a2990d7ba7b57108b47dabf
   y[8]        beadb2b25b3cacc1ac0cef346cbb90fb
               044beee4fac2603a442bdf7e507243b7
   y[9]        319c9944b1586e899d431c7f91bcccc8
               690dbf59b28386b2315f3d36ef2eaa3c
   y[10]       f30b2b51f48b71b003dfb08249484201
               043f65f5a3ef6bbd61ddfee81aca9ce6
   y[11]       0081262a00000480dcbc9a3da6fbef5c
               1c0a55e48a0e729f9184fcb1407c3152
   y[12]       9db268f6fe50032a363c9801306837fa
               fabdf957fd97eafc80dbd165e435d0e2
   y[13]       dfd836a28b354023924b6fb7e48bc0b3
               ed95eea64c2d402f4d734c8dc26f3ac5
   y[14]       91825daef01eae3c38e3328d00a77dc6
               57034f287ccb0f0e1c9a7cbdc828f627
   y[15]       205e4737b84b58376551d44c12c3c215
               c812a0970789c83de51d6ad787271963
   y[16]       327f0a5fbb6b5907dec02c9a90934af5
               a1c63b72c82653605d1dcce51596b3c2
   y[17]       b45696689f2eb382007497557692caac
               4d57b5de9f5569bc2ad0137fd47fb47e
   y[18]       664fcb6db4971f5b3e07aceda9ac130e
               9f38182de994cff192ec0e82fd6d4cb7
   y[19]       f3fe00812589b7a7ce51544045643301
               6b84a59bec6619a1c6c0b37dd1450ed4
   y[20]       f2d8b584410ceda8025f5d2d8dd0d217
               6fc1cf2cc06fa8c82bed4d944e71339e
   y[21]       ce780fd025bd41ec34ebff9d4270a322
               4e019fcb444474d482fd2dbe75efb203
   y[22]       89cc10cd600abb54c47ede93e08c114e
               db04117d714dc1d525e11bed8756192f
   y[23]       929d15462b939ff3f52f2252da2ed64d
               8fae88818b1efa2c7b08c8794fb1b214
   y[24]       aa233db3162833141ea4383f1a6f120b
               e1db82ce3630b3429114463157a64e91
   y[25]       234d475e2f79cbf05e4db6a9407d72c6
               bff7d1198b5c4d6aad2831db61274993
   y[26]       715a0182c7dc8089e32c8531deed4f74
               31c07c02195eba2ef91efb5613c37af7
   y[27]       ae0c066babc69369700e1dd26eddc0d2
               16c781d56e4ce47e3303fa73007ff7b9
   y[28]       49ef23be2aa4dbf25206fe45c20dd888
               395b2526391a724996a44156beac8082
   y[29]       12858792bf8e74cba49dee5e8812e019
               da87454bff9e847ed83db07af3137430
   y[30]       82f880a278f682c2bd0ad6887cb59f65
               2e155987d61bbf6a88d36ee93b6072e6
   y[31]       656d9ccbaae3d655852e38deb3a2dcf8
               058dc9fb6f2ab3d3b3539eb77b248a66
   y[32]       1091d05eb6e2f297774fe6053598457c
               c61908318de4b826f0fc86d4bb117d33
   y[33]       e865aa805009cc2918d9c2f840c4da43
               a703ad9f5b5806163d7161696b5a0adc
   --------------------------------------------
   LMS type    00000005                         # LM_SHA256_M32_H5
   path[0]     d5c0d1bebb06048ed6fe2ef2c6cef305
               b3ed633941ebc8b3bec9738754cddd60
   path[1]     e1920ada52f43d055b5031cee6192520
               d6a5115514851ce7fd448d4a39fae2ab
   path[2]     2335b525f484e9b40d6a4a969394843b
               dcf6d14c48e8015e08ab92662c05c6e9
   path[3]     f90b65a7a6201689999f32bfd368e5e3
               ec9cb70ac7b8399003f175c40885081a
   path[4]     09ab3034911fe125631051df0408b394
               6b0bde790911e8978ba07dd56c73e7ee



*/

#[test]
fn lms_kat() {
    use rustc_serialize::hex::FromHex;

    let msg = "54686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a".from_hex().unwrap();

    // LM_SHA256_M32_H5 / LMOTS_SHA256_N32_W8
    let pk = "000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878".from_hex().unwrap();
}

#[test]
fn lms_5_sign_kat() {
    use rustc_serialize::hex::FromHex;

    let seed = vec![0xFF; 48];
    let mut sk = LmsPrivateKey::new(&seed).unwrap();

    let msg = "616263".from_hex().unwrap();
    let rnd = vec![0; 32];
    let sig = sk.sign(&msg, &rnd).unwrap();

    let pk = sk.public_key().unwrap();

    assert!(pk.verify(&msg, &sig).unwrap());

}

#[test]
fn lms_5_verify_kat() {
    use rustc_serialize::hex::FromHex;

    // Generated by reference implementation H5 LMS signature

    let msg = "616263".from_hex().unwrap();

    // leading 00000001 (HSS depth) removed
    let pk = "0000000500000004B18A52569E753169FD4310819DBC5409F1FADCF57D031AB6DCFE30CF61F9C9E4A30172F379DD3EA5CDD124C4842D2F1D".from_hex().unwrap();

    let pk = LmsPublicKey::from_bytes(&pk).unwrap();

    /*
    In the specific case of L=1, the format of an HSS signature is

    u32str(0) || sig[0]

    Here leading u32str(0) was removed leaving an LMS signature
     */
    let sig1 = "0000000000000004FC3729EE1515E60338487FDFE7B60B879A4DB832D52A162A7AC296FEF856D70371329AF51D978B60228CD8BC406AAFF9536C2B0B3DA38F493D46FB6E6194355D29F312627D0D15D5EA144724E9C89908A8DD559AD27A9FABD2F0A01B4322B8C6E237C0F45AEAF393A124D28B1DBEDD3FD7EA02BC5D0B295363A9D73E1FF7681673A00331DD4F26E4A1A7D6C94C1E9DFEE2050761089DE6AFD95B3D7B8B2F65CE8C94A154E977A6A7005FB78364F14D64C3E8B118A4DD42C598A86FCE1E5D66E94AEC0745C8A252E80A72751C42CF38BA2C3F0F782CAAD2EE7C40FA89283626CFC8F717019B650B28647457789551366FC6C048EE93E47494156B3D4A7130B003617E222A21C50BC7B03DF55590C57AFEC8968B9053C21FEB7DEDDC18A4A6A40A765A897BF364DFC63DD9DEC7E393F1E704F7CAB5938579C04A81766BCCDD905635112FCDF0D0544B38339EEC6FE03F1411C2C1450C777D734AA301339B77458106A03F90E6A3DAE26E851B1C65013B68B94AB3B1C4C8E59AECA58A6EE41CC683AC92957EED3F54EEBB4C3B79B68E4F5FE4B7FAD1F04DC002635A8FFB8E541D87263C98B70E234E5A7CEB65004107078C15BBBCC8F01DD54638B75C0BF93E12E5001E2EB6C68E8BD210999131FB473682F464173A68CA3E56EDC4CE41F28D16ACF7FB78734EB0C807F5C835FBE27B8B9850E9305F4143DCEBFAA82E5CCBFD96065DC6670FC37602AAE3B78D67DB18FBEE145B5A0510412C7AF1002D3485212876C17B7F018D69611FA589E3327A61FCD229DE59AAA9B0E9C1541126DAA5C8FD813F5063FEA22C784005C4421DC01F69E429DFFE77E1A1B2AFF81C963CE86FB1C49E2496FA91CAD70BEA2DB878B64648C3AA7DC66FA4D28D43917C70561AE5F3A9017C9F4A1472B9AAF24AF757C6A8978077AA1B73CF6803D81CBCCDC3ACD18772D3E44FC38AAC4B9660E222CFFCCB523D18E6FD1B54645D62B0FEA43FC191CEC7E9F4F71F1CBD00D0745372DB6E69C9C9980441BDE9F4718ADDE06C9BE25BC0CFA5939323974AD2D634619330D255E6703F394FD876588E5930384D04E847E9FD8BD641186B72656D660BDCACA7C31522869D4C82A5DF2ABA59391C97958F50C95C995ACE948880BE4F97B3BC3966BA3D52B41E5356B26151C6402FABFF7D5036AA1E4450A7B09F8E76D320307004329C6906C622D73F713BEE593ED5915484F818A44EC817CE2498888E83A4B0645BDE2C9AC1D3B915C0F6F6490870CEC7AA232FEE2E29DA41F0E1369704578046383E8BEBB5C0DA91ABD8C6BE7FB9403A8D9B10D03D494B11EF7D89F62B87C49826A34F407E842030181EFFB063A57B4887F9B8B9573F8B67462D2E8FD6A6D8A676092D8483F3C0440C2098980DEECC4926F52FC28C131348C1E99CCF95F784AB6BC42043485512884139ABF9993F76EBF83E02C46F750F063C9BE1146EB9850DFBBBD715EE5B718615A669BBFAD4592FCFB6DF6AF2D6D14CDF7743F4B09D90C274C46080C02301EB93224C5F15EE86B0FC0BE859314EA154D2D1C0FE1D0486037506C253446466817EE1287329870E85D34900000005266FFD0B8597C600B46C3250A6BFAC68951CCB50D8BD7A8EEF2062547E5CB7F2EC6156E6BEDA3A583C9C7FA3C723DF11D351452E6F91EBA105EEC661ED49FBE226CABE5CA19CA1F42F5C3BD1CD047327670138F3A113A7E3A304F107BFB564E88416F14342135B38C7BF0D2571BE4D75CAA4E960B2E377DC87C29A10DEB4578CF046A3BA08582C59B339B1ED9970E8A18524665A56B150440DFBF5DC5765BD55".from_hex().unwrap();

    let accepted = pk.verify(&msg, &sig1).unwrap();
    assert!(accepted);

    let accepted = pk.verify(&[1,2,3], &sig1).unwrap();
    assert_eq!(accepted, false);
}

fn main() {
    //use rustc_serialize::hex::ToHex;

    //let mut entropy = mbedtls::rng::OsEntropy::new();
    //let mut rng = mbedtls::rng::CtrDrbg::new(&mut entropy, None).unwrap();

    let ots_seed = vec![0; N+16];
    let sk = LmsPrivateKey::new(&ots_seed).unwrap();

    println!("pk={}", sk.pk.to_hex());

    println!("ok");
}
