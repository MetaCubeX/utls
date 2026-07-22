package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// JLS BEGIN: ShadowQUIC JLS authentication and camouflage support.

// JLSUser is a ShadowQUIC JLS user. Username maps to rustls-jls user_iv,
// and Password maps to rustls-jls user_pwd.
type JLSUser struct {
	Username string
	Password string
}

// JLSConfig enables ShadowQUIC JLS authentication and camouflage.
type JLSConfig struct {
	Enable bool

	// Client-side field.
	User JLSUser

	// Server-side fields.
	Users      []JLSUser
	ServerName string
}

// JLSStatus reports ShadowQUIC JLS authentication status for a connection.
type JLSStatus uint8

const (
	JLSDisabled JLSStatus = iota
	JLSUnauthenticated
	JLSAuthenticated
)

// JLSState reports ShadowQUIC JLS authentication state for a connection.
type JLSState struct {
	Status JLSStatus
	User   string
}

type jlsState uint8

const (
	jlsStateDisabled jlsState = iota
	jlsStateNotAuthed
	jlsStateAuthSuccess
	jlsStateAuthFailed
)

const (
	jlsHandshakeHeaderLen              = 4 // uint8 message type and uint24 message length
	jlsHelloLegacyVersionLen           = 2
	jlsHelloRandomLen                  = 32
	jlsHelloRandomOffset               = jlsHandshakeHeaderLen + jlsHelloLegacyVersionLen
	jlsRandomSeedLen                   = jlsHelloRandomLen / 2
	jlsAuthenticatedSessionExtraPrefix = "jls-tls\x00\x01authenticated\x00"
)

// ErrJLSAuthFailed is returned when ShadowQUIC JLS authentication fails.
var ErrJLSAuthFailed = errors.New("tls: jls authentication failed")

var errJLSAuthFailed = ErrJLSAuthFailed

func (c *Config) jlsConfig() *JLSConfig {
	if c == nil || c.JLSConfig == nil || !c.JLSConfig.Enable {
		return nil
	}
	return c.JLSConfig
}

func (c *Conn) jlsAuthenticated() bool {
	return c.jlsState == jlsStateAuthSuccess
}

func (c *Conn) markJLSAuthenticatedSession(session *SessionState) {
	cfg := c.config.jlsConfig()
	if c.jlsAuthenticated() && cfg != nil {
		session.Extra = append(
			session.Extra,
			jlsAuthenticatedSessionExtra(session, cfg.User, c.clientSessionCacheKey()),
		)
	}
}

func (c *Conn) canResumeJLSAuthenticatedSession(session *SessionState) bool {
	cfg := c.config.jlsConfig()
	if cfg == nil || !session.isClient || session.version != VersionTLS13 {
		return false
	}
	want := jlsAuthenticatedSessionExtra(session, cfg.User, c.clientSessionCacheKey())
	for _, extra := range session.Extra {
		if hmac.Equal(extra, want) {
			return true
		}
	}
	return false
}

func jlsAuthenticatedSessionExtra(session *SessionState, user JLSUser, sessionKey string) []byte {
	// Key the local marker with the ticket PSK and bind it to the JLS identity
	// and cache key, preserving loadSession's cross-server cache protection.
	// Password material stays out of persistent metadata to avoid an offline verifier.
	mac := hmac.New(sha256.New, session.secret)
	mac.Write([]byte(jlsAuthenticatedSessionExtraPrefix))
	var lengths [8]byte
	binary.BigEndian.PutUint32(lengths[:4], uint32(len(user.Username)))
	binary.BigEndian.PutUint32(lengths[4:], uint32(len(sessionKey)))
	mac.Write(lengths[:])
	mac.Write([]byte(user.Username))
	mac.Write([]byte(sessionKey))
	return append([]byte(jlsAuthenticatedSessionExtraPrefix), mac.Sum(nil)...)
}

func (c *Conn) jlsStatus() JLSStatus {
	if c.config.jlsConfig() == nil {
		return JLSDisabled
	}
	if c.jlsAuthenticated() {
		return JLSAuthenticated
	}
	return JLSUnauthenticated
}

func (c *Conn) canFallbackJLS() bool {
	cfg := c.config.jlsConfig()
	return !c.isClient && c.quic == nil && cfg != nil && c.bytesSent == 0
}

func jlsBuildFakeRandom(user JLSUser, random16, authData []byte, random io.Reader) ([]byte, error) {
	if len(random16) != jlsRandomSeedLen {
		return nil, errors.New("tls: jls random seed must be 16 bytes")
	}
	nonceHash := sha256.New()
	nonceHash.Write([]byte(user.Username))
	nonceHash.Write(authData)
	nonce := nonceHash.Sum(nil)

	keyHash := sha256.New()
	keyHash.Write([]byte(user.Password))
	keyHash.Write(authData)
	key := keyHash.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, sha256.Size)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), random16...)
	// JLS v3 reserves the TLS downgrade canaries and the HRR random suffix.
	// Regenerate N instead of emitting a FakeRandom ending in one of them.
	for {
		fakeRandom := aead.Seal(nil, nonce, seed, nil)
		if !jlsHasForbiddenRandomSuffix(fakeRandom) {
			return fakeRandom, nil
		}
		if _, err := io.ReadFull(random, seed); err != nil {
			return nil, err
		}
	}
}

func jlsHasForbiddenRandomSuffix(random []byte) bool {
	const suffixLen = len(downgradeCanaryTLS12)
	if len(random) < suffixLen {
		return false
	}
	suffix := random[len(random)-suffixLen:]
	return string(suffix) == downgradeCanaryTLS12 ||
		string(suffix) == downgradeCanaryTLS11 ||
		bytes.Equal(suffix, helloRetryRequestRandom[len(helloRetryRequestRandom)-suffixLen:])
}

func jlsCheckFakeRandom(user JLSUser, fakeRandom, authData []byte) bool {
	if len(fakeRandom) != jlsHelloRandomLen {
		return false
	}
	nonceHash := sha256.New()
	nonceHash.Write([]byte(user.Username))
	nonceHash.Write(authData)
	nonce := nonceHash.Sum(nil)

	keyHash := sha256.New()
	keyHash.Write([]byte(user.Password))
	keyHash.Write(authData)
	key := keyHash.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	aead, err := cipher.NewGCMWithNonceSize(block, sha256.Size)
	if err != nil {
		return false
	}
	plain, err := aead.Open(nil, nonce, fakeRandom, nil)
	return err == nil && len(plain) == jlsRandomSeedLen
}

func (c *Conn) applyJLSClientHello(hello *clientHelloMsg, session *SessionState, binderKey []byte) error {
	if err := c.applyJLSClientHelloRandom(hello); err != nil {
		return err
	}
	if c.config.jlsConfig() == nil {
		return nil
	}

	if session != nil && binderKey != nil {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		if suite == nil {
			return errors.New("tls: jls failed to find tls13 cipher suite for psk binder")
		}
		transcript := suite.hash.New()
		if err := computeAndUpdatePSK(hello, binderKey, transcript, suite.finishedHash); err != nil {
			return err
		}
		if hello.original != nil {
			return jlsPatchClientHelloBinders(hello)
		}
	}
	return nil
}

func (c *Conn) applyJLSClientHelloRandom(hello *clientHelloMsg) error {
	cfg := c.config.jlsConfig()
	if cfg == nil {
		c.jlsState = jlsStateDisabled
		return nil
	}
	if c.config.EncryptedClientHelloConfigList != nil {
		return errors.New("tls: jls cannot be used with encrypted client hello")
	}
	if len(hello.random) != jlsHelloRandomLen {
		return errors.New("tls: jls client hello random is invalid")
	}
	c.jlsState = jlsStateNotAuthed

	var (
		authData []byte
		err      error
	)
	if hello.original != nil {
		authData, err = jlsClientHelloWireAuthData(hello)
	} else {
		authData, err = jlsClientHelloAuthData(hello)
	}
	if err != nil {
		return err
	}
	fakeRandom, err := jlsBuildFakeRandom(cfg.User, hello.random[:jlsRandomSeedLen], authData, c.config.rand())
	if err != nil {
		return err
	}
	hello.random = fakeRandom
	if hello.original != nil {
		if len(hello.original) < jlsHelloRandomOffset+jlsHelloRandomLen {
			return errors.New("tls: jls client hello too short")
		}
		copy(hello.original[jlsHelloRandomOffset:jlsHelloRandomOffset+jlsHelloRandomLen], fakeRandom)
	}
	return nil
}

func jlsClientHelloAuthData(hello *clientHelloMsg) ([]byte, error) {
	clone := hello.clone()
	clone.original = nil
	clone.random = make([]byte, jlsHelloRandomLen)
	for i := range clone.pskBinders {
		clone.pskBinders[i] = make([]byte, len(clone.pskBinders[i]))
	}
	return clone.marshal()
}

func (c *Conn) authenticateJLSServerHello(serverHello *serverHelloMsg) error {
	cfg := c.config.jlsConfig()
	if cfg == nil {
		c.jlsState = jlsStateDisabled
		return nil
	}
	authData, err := jlsServerHelloAuthData(serverHello)
	if err != nil {
		return err
	}
	if !jlsCheckFakeRandom(cfg.User, serverHello.random, authData) {
		c.jlsState = jlsStateAuthFailed
		return nil
	}
	c.jlsState = jlsStateAuthSuccess
	c.jlsUser = cfg.User
	return nil
}

func jlsServerHelloAuthData(hello *serverHelloMsg) ([]byte, error) {
	var wire []byte
	if hello.original != nil {
		wire = hello.original
	} else {
		var err error
		wire, err = hello.marshal()
		if err != nil {
			return nil, err
		}
	}
	msg := append([]byte(nil), wire...)
	if len(msg) < jlsHelloRandomOffset+jlsHelloRandomLen {
		return nil, errors.New("tls: jls server hello too short")
	}
	jlsZero(msg[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	return msg, nil
}

func (c *Conn) authenticateJLSClientHello(hello *clientHelloMsg) error {
	cfg := c.config.jlsConfig()
	if cfg == nil {
		c.jlsState = jlsStateDisabled
		return nil
	}
	c.jlsState = jlsStateNotAuthed
	authData, err := jlsClientHelloWireAuthData(hello)
	if err != nil {
		c.jlsState = jlsStateAuthFailed
		return err
	}
	if !cfg.checkServerName(hello.serverName) {
		c.jlsState = jlsStateAuthFailed
		return errJLSAuthFailed
	}
	for _, user := range cfg.Users {
		if jlsCheckFakeRandom(user, hello.random, authData) {
			c.jlsState = jlsStateAuthSuccess
			c.jlsUser = user
			return nil
		}
	}
	c.jlsState = jlsStateAuthFailed
	return errJLSAuthFailed
}

func jlsClientHelloWireAuthData(hello *clientHelloMsg) ([]byte, error) {
	var msg []byte
	if hello.original != nil {
		msg = append([]byte(nil), hello.original...)
	} else {
		var err error
		msg, err = jlsClientHelloAuthData(hello)
		if err != nil {
			return nil, err
		}
		return msg, nil
	}
	if len(msg) < jlsHelloRandomOffset+jlsHelloRandomLen {
		return nil, errors.New("tls: jls client hello too short")
	}
	jlsZero(msg[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	return jlsZeroPSKBinders(msg, hello.pskBinders)
}

func jlsZeroPSKBinders(msg []byte, binders [][]byte) ([]byte, error) {
	if len(binders) == 0 {
		return msg, nil
	}
	bindersLen := 2
	for _, binder := range binders {
		if len(binder) > 0xff {
			return nil, errors.New("tls: jls psk binder too large")
		}
		bindersLen += 1 + len(binder)
	}
	if bindersLen > len(msg) || bindersLen-2 > 0xffff {
		return nil, errors.New("tls: jls malformed psk binders")
	}
	off := len(msg) - bindersLen
	binary.BigEndian.PutUint16(msg[off:off+2], uint16(bindersLen-2))
	off += 2
	for _, binder := range binders {
		msg[off] = byte(len(binder))
		off++
		jlsZero(msg[off : off+len(binder)])
		off += len(binder)
	}
	return msg, nil
}

func jlsPatchClientHelloBinders(hello *clientHelloMsg) error {
	if len(hello.pskBinders) == 0 {
		return nil
	}
	bindersLen := 2
	for _, binder := range hello.pskBinders {
		if len(binder) > 0xff {
			return errors.New("tls: jls psk binder too large")
		}
		bindersLen += 1 + len(binder)
	}
	if bindersLen > len(hello.original) || bindersLen-2 > 0xffff {
		return errors.New("tls: jls malformed psk binders")
	}
	off := len(hello.original) - bindersLen
	binary.BigEndian.PutUint16(hello.original[off:off+2], uint16(bindersLen-2))
	off += 2
	for _, binder := range hello.pskBinders {
		hello.original[off] = byte(len(binder))
		off++
		copy(hello.original[off:off+len(binder)], binder)
		off += len(binder)
	}
	return nil
}

func jlsZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (cfg *JLSConfig) checkServerName(serverName string) bool {
	if cfg == nil || cfg.ServerName == "" {
		return true
	}
	return serverName == cfg.ServerName
}

// JLS END
