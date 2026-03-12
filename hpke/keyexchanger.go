package hpke

import "crypto/ecdh"

// ecdhKeyExchanger is an interface for an opaque private key that can be used for
// key exchange operations. For example, an ECDH key kept in a hardware module.
//
// It is implemented by [ecdh.PrivateKey].
type ecdhKeyExchanger interface {
	PublicKey() *ecdh.PublicKey
	Curve() ecdh.Curve
	ECDH(*ecdh.PublicKey) ([]byte, error)
}
