use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use rand::{distributions::Alphanumeric, Rng};


#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Input {
    pub source: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Output {
    pub destination: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RawTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}
/// Create digital signature of a transaction
pub fn sign(t: &RawTransaction, key: &Ed25519KeyPair) -> Signature {
    let serialized = serde_json::to_vec(t).unwrap(); // Serialize the transaction
    key.sign(&serialized)
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &RawTransaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let serialized = serde_json::to_vec(t).unwrap();
    let verify_alg = &ring::signature::ED25519;
    ring::signature::UnparsedPublicKey::new(verify_alg, public_key).verify(&serialized, signature.as_ref()).is_ok()
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;

    pub fn generate_random_transaction() -> RawTransaction {
        let mut rng = rand::thread_rng();
        // Adjust the gen_range call to ensure compatibility
        let num_inputs = rng.gen_range(1, 3);  // Generates a number from 1 to 3 inclusive
        let num_outputs = rng.gen_range(1,3); // Generates a number from 1 to 3 inclusive

        let inputs = (0..num_inputs).map(|_| Input {
            source: rng.sample_iter(&Alphanumeric).take(10).map(char::from).collect(),
            amount: rng.gen(),
        }).collect();

        let outputs = (0..num_outputs).map(|_| Output {
            destination: rng.sample_iter(&Alphanumeric).take(10).map(char::from).collect(),
            amount: rng.gen(),
        }).collect();

        RawTransaction { inputs, outputs }
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
}
