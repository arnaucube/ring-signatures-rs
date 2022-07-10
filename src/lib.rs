extern crate ark_ed_on_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve, TEModelParameters};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsParameters, EdwardsProjective, FqParameters, Fr};
use ark_ff::{fields::PrimeField, BigInteger, Fp256};
use ark_std::{UniformRand, Zero};
use sha2::{Digest, Sha256};

const GX: Fp256<FqParameters> = <EdwardsParameters as TEModelParameters>::AFFINE_GENERATOR_COEFFS.0;
const GY: Fp256<FqParameters> = <EdwardsParameters as TEModelParameters>::AFFINE_GENERATOR_COEFFS.1;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref G_AFFINE: EdwardsAffine = EdwardsAffine::new(GX, GY);
    pub static ref G: EdwardsProjective = G_AFFINE.into_projective();
}

pub type PublicKey = EdwardsProjective;
pub type Signature = (Fr, Vec<Fr>);

#[derive(Debug, PartialEq)]
pub struct KeyPair {
    sk: Fr,
    pub pk: PublicKey,
}

pub fn new_key() -> KeyPair {
    let mut rng = ark_std::rand::thread_rng();
    let sk: Fr = Fr::rand(&mut rng);
    // let sk: Fr = UniformRand::rand(&mut rng);

    let pk = G.mul(sk.into_repr());
    KeyPair { sk, pk }
}

#[allow(clippy::many_single_char_names)]
impl KeyPair {
    pub fn key_image(&self) -> EdwardsProjective {
        hash_to_point(self.pk).mul(self.sk.into_repr())
    }

    pub fn sign(&self, ring: Vec<PublicKey>, m: Vec<u8>) -> Result<Signature, String> {
        let ring_size = ring.len();
        // determine pi (the position of signer's public key in R
        let mut pi = 0;
        let mut found = false;
        // for i in 0..ring_size {
        for (i, ring_key) in ring.iter().enumerate() {
            if &self.pk == ring_key {
                pi = i;
                found = true;
                break;
            }
        }
        if !found {
            return Err("key not found in the ring".to_string());
        }

        let mut rng = ark_std::rand::thread_rng();
        let a: Fr = Fr::rand(&mut rng);
        let mut r: Vec<Fr> = vec![Fr::zero(); ring_size];

        // for i \in {1, 2, ..., n} \ {i=pi}
        #[allow(clippy::needless_range_loop)]
        for i in 0..ring_size {
            if i == pi {
                continue;
            }
            r[i] = Fr::rand(&mut rng);
        }

        let mut c: Vec<Fr> = vec![Fr::zero(); ring_size];
        // c_{pi+1}
        let pi1 = (pi + 1) % ring_size;
        c[pi1] = hash(
            &ring,
            &m,
            G.mul(a.into_repr()),
            hash_to_point(ring[pi]).mul(a.into_repr()),
        );

        let key_image = self.key_image();
        // do c_{i+1} from i=pi+1 to pi-1:
        for j in 0..(ring_size - 1) {
            let i = (pi1 + j) % ring_size;
            let i1 = (pi1 + j + 1) % ring_size;
            c[i1] = hash(
                &ring,
                &m,
                G.mul(r[i].into_repr()) + ring[i].mul(c[i].into_repr()),
                hash_to_point(ring[i]).mul(r[i].into_repr()) + key_image.mul(c[i].into_repr()),
            );
            println!("i {:?}, {:?}", i, c[i1]);
        }

        // compute r_pi
        r[pi] = a - c[pi] * self.sk;
        Ok((c[0], r))
    }
}

pub fn verify(
    ring: Vec<PublicKey>,
    m: Vec<u8>,
    key_image: EdwardsProjective,
    sig: Signature,
) -> bool {
    let ring_size = ring.len();

    let c1 = sig.0;
    let r = sig.1;
    if ring_size != r.len() {
        return false;
    }
    // TODO check that key_image \in G (EC), by l * key_image == 0

    let mut c: Vec<Fr> = vec![Fr::zero(); ring_size];
    c[0] = c1;
    for j in 0..ring_size {
        let i = j % ring_size;
        let i1 = (j + 1) % ring_size;
        c[i1] = hash(
            &ring,
            &m,
            G.mul(r[i].into_repr()) + ring[i].mul(c[i].into_repr()),
            hash_to_point(ring[i]).mul(r[i].into_repr()) + key_image.mul(c[i].into_repr()),
        );
    }

    println!("c {:?}\n{:?}", c1, c[0]);

    if c1 == c[0] {
        return true;
    }
    false
}

fn hash_to_point(a: EdwardsProjective) -> EdwardsProjective {
    // TODO use a proper hash_to_point method
    let mut v: Vec<u8> = Vec::new();
    v.append(&mut a.into_affine().x.into_repr().to_bytes_le());
    v.append(&mut a.into_affine().y.into_repr().to_bytes_le());
    let mut hasher = Sha256::new();
    hasher.update(v);
    let h = hasher.finalize();
    let v = Fr::from_le_bytes_mod_order(&h[..]);

    G.mul(v.into_repr())
}

fn hash(ring: &[PublicKey], m: &[u8], a: EdwardsProjective, b: EdwardsProjective) -> Fr {
    let mut v: Vec<u8> = Vec::new();

    for ring_key in ring.iter() {
        v.append(&mut ring_key.into_affine().x.into_repr().to_bytes_le());
        v.append(&mut ring_key.into_affine().y.into_repr().to_bytes_le());
    }
    v.append(&mut m.to_vec());
    v.append(&mut a.into_affine().x.into_repr().to_bytes_le());
    v.append(&mut a.into_affine().y.into_repr().to_bytes_le());
    v.append(&mut b.into_affine().x.into_repr().to_bytes_le());
    v.append(&mut b.into_affine().y.into_repr().to_bytes_le());

    Fr::from_le_bytes_mod_order(&Sha256::new().chain_update(v).finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_bLSAG() {
        let n = 5; // ring size
        let pi = 3; // position of prover key in the ring

        let k_pi = new_key();
        println!("{:?}", k_pi);

        // generate other n public keys
        let mut ring: Vec<PublicKey> = vec![G.clone(); n];
        for i in 0..n {
            let k = new_key();
            ring[i] = k.pk;
        }
        // set K_pi
        ring[pi] = k_pi.pk;

        let m: Vec<u8> = vec![1, 2, 3, 4];
        let sig = k_pi.sign(ring.clone(), m.clone()).unwrap();
        println!("sig {:?}", sig);

        let key_image = k_pi.key_image();

        let v = verify(ring.clone(), m.clone(), key_image, sig.clone());
        println!("v {:?}", v);
        assert!(v);

        let m: Vec<u8> = vec![1, 2, 3, 3];
        let v = verify(ring, m, key_image, sig);
        assert!(!v);
    }
}
