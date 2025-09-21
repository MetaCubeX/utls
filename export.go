package tls

import "crypto/x509"

func AesgcmPreferred(ciphers []uint16) bool { return isAESGCMPreferred(ciphers) }

func (c *Conn) PeerCertificates() []*x509.Certificate {
	return c.peerCertificates
}

func HasAESGCMHardwareSupport() bool {
	return hasAESGCMHardwareSupport
}
