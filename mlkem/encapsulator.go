package mlkem

// Decapsulator is an interface for an opaque private KEM key that can be used for
// decapsulation operations. For example, an ML-KEM key kept in a hardware module.
//
// It is implemented, for example, by [crypto/mlkem.DecapsulationKey768].
type Decapsulator interface {
	Encapsulator() Encapsulator
	Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
}

// Encapsulator is an interface for a public KEM key that can be used for
// encapsulation operations.
//
// It is implemented, for example, by [crypto/mlkem.EncapsulationKey768].
type Encapsulator interface {
	Bytes() []byte
	Encapsulate() (sharedKey, ciphertext []byte)
}

// Encapsulator returns the encapsulation key, like
// [DecapsulationKey768.EncapsulationKey].
//
// It implements [Decapsulator].
func (dk *DecapsulationKey768) Encapsulator() Encapsulator {
	return dk.EncapsulationKey()
}

var _ Decapsulator = (*DecapsulationKey768)(nil)

// Encapsulator returns the encapsulation key, like
// [DecapsulationKey1024.EncapsulationKey].
//
// It implements [Decapsulator].
func (dk *DecapsulationKey1024) Encapsulator() Encapsulator {
	return dk.EncapsulationKey()
}

var _ Decapsulator = (*DecapsulationKey1024)(nil)
