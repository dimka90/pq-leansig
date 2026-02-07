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

impl SecretKey {
    pub fn new(inner: LeanSecretKey) -> Self {
        Self { inner }
    }
    
    pub fn generate_keys<R: Rng>(rng: &mut R, activation_epoch: usize, num_active_epochs: usize) -> (PublicKey, SecretKey) {
        let (public_key, secret_key) = <LeanSignatureScheme as SignatureScheme>::key_gen(rng, activation_epoch, num_active_epochs);
        
        (PublicKey::new(public_key), Self::new(secret_key))
    }
    
    pub fn sign_message(&self, message: &[u8; MESSAGE_LENGTH], epoch: u32) -> Result<Signature, SigningError> {
        Ok(Signature::new(<LeanSignatureScheme as SignatureScheme>::sign(&self.inner, epoch, message).map_err(SigningError::SigningFailed)?))
    }
    
    
}

impl PublicKey {
    pub fn new(inner: LeanPublicKey) -> Self {
        Self { inner }
    }
}

impl Signature {
    pub fn new(inner: LeanSignature) -> Self {
        Self{ inner }
    }
    
    pub fn verify(&self, message: &[u8; MESSAGE_LENGTH], public_key: &PublicKey, epoch: u32) -> bool {
        <LeanSignatureScheme as SignatureScheme>::verify(&public_key.inner, epoch, message, &self.inner)
    }
}