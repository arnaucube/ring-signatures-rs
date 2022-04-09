extern crate ark_ed_on_bn254;
use ark_ec::{AffineCurve, ProjectiveCurve, TEModelParameters};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsParameters, EdwardsProjective, FqParameters, Fr};
use ark_ff::{bytes::FromBytes, fields::PrimeField, BigInteger, Fp256};
use ark_std::{rand, UniformRand, Zero};
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

impl KeyPair {
    pub fn key_image(&self) -> EdwardsProjective {
        hash_to_point(self.pk).mul(self.sk.into_repr())
    }

    pub fn sign(&self, ring: Vec<PublicKey>, m: Vec<u8>) -> Signature {
        let ring_size = ring.len();
        // determine pi (the position of signer's public key in R
        let mut pi = 0;
        let mut found = false;
        for i in 0..ring_size {
            if self.pk == ring[i] {
                pi = i;
                found = true;
                break;
            }
        }
        if !found {
            // error
            println!("key not found in the ring");
        }

        let mut rng = ark_std::rand::thread_rng();
        let a: Fr = Fr::rand(&mut rng);
        let mut r: Vec<Fr> = vec![Fr::zero(); ring_size];

        // for i \in {1, 2, ..., n} \ {i=pi}
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
        (c[0], r)
    }
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

fn hash(ring: &Vec<PublicKey>, m: &Vec<u8>, a: EdwardsProjective, b: EdwardsProjective) -> Fr {
    let mut v: Vec<u8> = Vec::new();

    for i in 0..ring.len() {
        v.append(&mut ring[i].into_affine().x.into_repr().to_bytes_le());
        v.append(&mut ring[i].into_affine().y.into_repr().to_bytes_le());
    }
    v.append(&mut m.clone());
    v.append(&mut a.into_affine().x.into_repr().to_bytes_le());
    v.append(&mut a.into_affine().y.into_repr().to_bytes_le());
    v.append(&mut b.into_affine().x.into_repr().to_bytes_le());
    v.append(&mut b.into_affine().y.into_repr().to_bytes_le());

    Fr::from_le_bytes_mod_order(&Sha256::new().chain_update(v).finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
}
