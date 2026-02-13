package leansig

import "fmt"

import "C"

type Keypair struct {
	ptr keypair
}

func GenerateKeyPair() {
	keys := C.leansig_keypair_generate(C.uint64_t(1), C.uint64_t(1), C.uint64_t(2))
	fmt.Printf("Pointer %p", &keys)
}
