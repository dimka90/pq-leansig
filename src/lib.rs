use leansig::signature::SignatureScheme;
use leansig::MESSAGE_LENGTH;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use rand::{SeedableRng, rngs::StdRng, Rng};
use thiserror::Error;
use std::ptr;
use std::slice;
use ssz::Decode;

pub type LeanSignatureScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type LeanPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
pub type LeanSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;
pub type LeanSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

#[repr(C)]
pub struct SecretKey {
    pub inner: LeanSecretKey,
}

#[repr(C)]
pub struct PublicKey {
    pub inner: LeanPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: LeanSignature,
}

// Keypair sturcture
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing failed")]
    SigningFailed(leansig::signature::SigningError),
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

    pub fn generate_keys<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (PublicKey, SecretKey) {
        let (public_key, secret_key) = <LeanSignatureScheme as SignatureScheme>::key_gen(
            rng,
            activation_epoch,
            num_active_epochs,
        );

        (PublicKey::new(public_key), Self::new(secret_key))
    }

    pub fn sign_message(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        epoch: u32,
    ) -> Result<Signature, SigningError> {
        Ok(Signature::new(
            <LeanSignatureScheme as SignatureScheme>::sign(&self.inner, epoch, message)
                .map_err(SigningError::SigningFailed)?,
        ))
    }
}

impl PublicKey {
    pub fn new(inner: LeanPublicKey) -> Self {
        Self { inner }
    }
}

impl Signature {
    pub fn new(inner: LeanSignature) -> Self {
        Self { inner }
    }

    pub fn verify(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        public_key: &PublicKey,
        epoch: u32,
    ) -> bool {
        <LeanSignatureScheme as SignatureScheme>::verify(
            &public_key.inner,
            epoch,
            message,
            &self.inner,
        )
    }
}

// FFI functions for Golang interop
//
// Returns a pointer to the keypair
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_generate(
    seed: u64,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut Keypair {
    let mut rng = StdRng::seed_from_u64(seed);

    let (public_key, secret_key) =
        SecretKey::generate_keys(&mut rng, activation_epoch, num_active_epochs);

    let keypair = Box::new(Keypair {
        public_key,
        secret_key,
    });

    Box::into_raw(keypair)
}

// Reconstruct a key pair from SSZ-encoded secret and public keys
// Returns a pointer to the KeyPair or null on error
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_from_ssz(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize
) -> *mut Keypair {
    if secret_key_ptr.is_null() || public_key_ptr.is_null() {
        return ptr::null_mut();
    }
    
    unsafe {
        let sk_slice = slice::from_raw_parts(secret_key_ptr, secret_key_len);
        let pk_slice = slice::from_raw_parts(public_key_ptr, public_key_len);
        
        let secret_key: LeanSecretKey = match LeanSecretKey::from_ssz_bytes(sk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut()
        };
        
        let public_key: LeanPublicKey = match LeanPublicKey::from_ssz_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut()
        };
        
        let keypair = Box::new(Keypair {
            public_key: PublicKey::new(public_key),
            secret_key: SecretKey::new(secret_key),
        });
        
        Box::into_raw(keypair)
            
        
    }
}
