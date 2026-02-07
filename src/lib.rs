use std::error;

use leansig::signature::SignatureScheme;
use leansig::MESSAGE_LENGTH;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use rand::Rng;
use thiserror::Error;


pub type LeanSignatureScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type LeanPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
pub type LeanSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;
pub type LeanSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

#[repr(C)]
pub struct SecretKey {
    pub inner: LeanSecretKey
}

#[repr(C)]
pub struct PublicKey {
    pub inner: LeanPublicKey
}

#[repr(C)]
pub struct Signature {
    pub inner: LeanSignature
}

// Keypair sturcture
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing failed")]
    SigningFailed(leansig::signature::SigningError)
}

#[derive(Debug, Error)]
pub enum SignatureVerificationError {
    #[error("Verification failed")]
    VerificationFailed,
}