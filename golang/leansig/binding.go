package leansig

/*
#cgo LDFLAGS: -L../rust/target/release -lpq_leansig
#include <stdint.h>
#include <stdlib.h>

typedef struct SecretKey {
    void* inner;
} SecretKey;

typedef struct PublicKey {
    void* inner;
} PublicKey;

typedef struct Keypair {
    PublicKey* public_key;
    SecretKey* secret_key;
} Keypair;

// Function declarations
Keypair* leansig_keypair_generate(uint64_t seed, size_t activation_epoch, size_t num_active_epochs);
void leansig_keypair_free(Keypair* keypair);
PublicKey* leansig_keypair_get_public_key(Keypair* keypair);
SecretKey* leansig_keypair_get_private_key(Keypair* keypair);
*/
import "C"

// Type aliases
type cKeypair = *C.Keypair

// type cPublicKey = *C.PublicKey
// type cSecretKey = *C.SecretKey
