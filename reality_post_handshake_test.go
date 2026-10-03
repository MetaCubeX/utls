package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func init() {
	// Keep probes fast in tests. Set once for the whole package so that no
	// probe goroutine can race with a later test changing them.
	realityPostHandshakeCollectWindow = 500 * time.Millisecond
	realityPostHandshakeProbeTimeout = 2 * time.Second
}

const realityTestServerName = "example.golang"

var (
	realityTestShortID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	realityTestMarker  = []byte("REALITY application data marker")
	realityTestSuites  = []uint16{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384}
)

// realityTestTarget is a local TLS 1.3 server standing in for the REALITY
// destination. After each completed handshake it writes one application_data
// record per entry of postRecords for the negotiated ALPN, then either hangs
// up without close_notify or stays open until the peer closes.
type realityTestTarget struct {
	ln          net.Listener
	config      *Config
	postRecords map[string][]int
	hangUp      bool

	accepted  atomic.Int32 // TCP connections accepted (live REALITY mirrors and probes)
	completed atomic.Int32 // handshakes completed (only probes and direct clients)
}

func realityTestTargetConfig(nextProtos []string, sessionTickets bool) *Config {
	config := testConfig.Clone()
	config.MinVersion = VersionTLS13
	config.DynamicRecordSizingDisabled = true
	config.SessionTicketsDisabled = !sessionTickets
	config.NextProtos = nextProtos
	return config
}

func newRealityTestTarget(t *testing.T, config *Config, postRecords map[string][]int, hangUp bool) *realityTestTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tt := &realityTestTarget{ln: ln, config: config, postRecords: postRecords, hangUp: hangUp}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			tt.accepted.Add(1)
			go tt.handle(raw)
		}
	}()
	return tt
}

func (tt *realityTestTarget) handle(raw net.Conn) {
	defer raw.Close()
	tc := Server(raw, tt.config)
	if err := tc.Handshake(); err != nil {
		return
	}
	tt.completed.Add(1)
	for _, n := range tt.postRecords[tc.ConnectionState().NegotiatedProtocol] {
		if _, err := tc.Write(make([]byte, n)); err != nil {
			return
		}
	}
	if tt.hangUp {
		return
	}
	io.Copy(io.Discard, tc)
}

func (tt *realityTestTarget) addr() string { return tt.ln.Addr().String() }

func newRealityTestConfig(t *testing.T, dest string) (*RealityConfig, *ecdh.PublicKey) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	config := &RealityConfig{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        dest,
		ServerNames: map[string]bool{realityTestServerName: true},
		PrivateKey:  priv,
		ShortIds:    map[[8]byte]bool{realityTestShortID: true},
	}
	config.SessionTicketsDisabled = true
	return config, pubKey
}

// newRealityTestServer accepts connections, runs RealityServer on each and,
// once the REALITY handshake completed, writes realityTestMarker.
func newRealityTestServer(t *testing.T, config *RealityConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c, err := RealityServer(context.Background(), raw, config)
				if err != nil {
					return
				}
				defer c.Close()
				if _, err := c.Write(realityTestMarker); err != nil {
					return
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// realityRecordingConn keeps a copy of everything read from the wrapped connection.
type realityRecordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *realityRecordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.buf = append(c.buf, b[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *realityRecordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// realityTestRecordLens splits a raw TLS stream into records and returns
// their wire lengths.
func realityTestRecordLens(t *testing.T, data []byte) []int {
	t.Helper()
	lens := []int{}
	for len(data) > 0 {
		if len(data) < recordHeaderLen {
			t.Fatalf("partial record header: % x", data)
		}
		n := recordHeaderLen + int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < n {
			t.Fatalf("partial record: want %d bytes, have %d", n, len(data))
		}
		lens = append(lens, n)
		data = data[n:]
	}
	return lens
}

// realityTestAuthenticate turns the prepared ClientHello of uconn into a
// REALITY ClientHello for the server public key pub, mirroring what a REALITY
// client does.
func realityTestAuthenticate(t *testing.T, uconn *UConn, pub *ecdh.PublicKey) {
	t.Helper()
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := uconn.HandshakeState.Hello
	rawSessionID := hello.Raw[39 : 39+32]
	for i := range rawSessionID {
		rawSessionID[i] = 0
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(time.Now().Unix()))
	copy(hello.SessionId[8:], realityTestShortID[:])
	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 2

	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.Ecdhe == nil {
		t.Fatal("no X25519 key share private key")
	}
	authKey, err := keys.Ecdhe.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
}

// realityTestDial connects to addr with a TLS 1.3 client offering alpn and
// suites. With pub set it authenticates as a REALITY client. It returns the
// connection, the raw recorder and the offset in the recorded stream of the
// first byte after the server Finished.
func realityTestDial(t *testing.T, addr string, pub *ecdh.PublicKey, alpn []string, suites []uint16) (*UConn, *realityRecordingConn, int) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	rec := &realityRecordingConn{Conn: raw}
	t.Cleanup(func() { raw.Close() })

	uconn := UClient(rec, &Config{
		ServerName:             realityTestServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, HelloCustom)
	spec := realityProbeClientHelloSpec(realityPostHandshakeKey{
		serverName:  realityTestServerName,
		alpn:        realityALPNMode(alpn),
		cipherSuite: suites[0],
	})
	spec.CipherSuites = append([]uint16(nil), suites...)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if pub != nil {
		realityTestAuthenticate(t, uconn, pub)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := uconn.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if v := uconn.ConnectionState().Version; v != VersionTLS13 {
		t.Fatalf("negotiated version %x, want TLS 1.3", v)
	}
	boundary := len(rec.bytes()) - uconn.rawInput.Len()
	return uconn, rec, boundary
}

// realityTestObserveTarget connects directly to the target and returns the
// wire lengths of every record the target sends after its Finished.
func realityTestObserveTarget(t *testing.T, tt *realityTestTarget, alpn []string, suites []uint16) []int {
	t.Helper()
	uconn, rec, boundary := realityTestDial(t, tt.addr(), nil, alpn, suites)
	defer uconn.Close()
	expect := 0
	for _, n := range tt.postRecords[uconn.ConnectionState().NegotiatedProtocol] {
		expect += n
	}
	if expect > 0 {
		if _, err := io.ReadFull(uconn, make([]byte, expect)); err != nil {
			t.Fatalf("reading target payload: %v", err)
		}
	} else {
		uconn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		io.ReadAll(uconn) // drain whatever the target sends; EOF or timeout ends it
	}
	return realityTestRecordLens(t, rec.bytes()[boundary:])
}

// realityTestConnect performs an authenticated REALITY handshake, reads the
// marker written by the REALITY server and returns the wire lengths of the
// records between the server Finished and the marker record, plus the
// negotiated cipher suite.
func realityTestConnect(t *testing.T, addr string, pub *ecdh.PublicKey, alpn []string, suites []uint16) ([]int, uint16) {
	t.Helper()
	uconn, rec, boundary := realityTestDial(t, addr, pub, alpn, suites)
	defer uconn.Close()
	uconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(realityTestMarker))
	if _, err := io.ReadFull(uconn, got); err != nil {
		t.Fatalf("reading marker: %v", err)
	}
	if string(got) != string(realityTestMarker) {
		t.Fatalf("marker = %q, want %q", got, realityTestMarker)
	}
	lens := realityTestRecordLens(t, rec.bytes()[boundary:])
	if len(lens) == 0 {
		t.Fatal("marker record not found in the recorded stream")
	}
	return lens[:len(lens)-1], uconn.ConnectionState().CipherSuite
}

func realityTestKey(config *RealityConfig, alpn []string, suite uint16) realityPostHandshakeKey {
	return realityPostHandshakeKey{
		network:     config.Type,
		dest:        config.Dest,
		serverName:  realityTestServerName,
		alpn:        realityALPNMode(alpn),
		cipherSuite: suite,
	}
}

// realityTestWaitProbe waits for the probe of key to finish. The entry must
// already exist, which is guaranteed once a REALITY connection for that key
// delivered the marker.
func realityTestWaitProbe(t *testing.T, config *RealityConfig, key realityPostHandshakeKey) *realityPostHandshakeEntry {
	t.Helper()
	cache := config.postHandshakeCache()
	cache.mu.Lock()
	e := cache.entries[key]
	cache.mu.Unlock()
	if e == nil {
		t.Fatalf("no probe entry for %+v", key)
	}
	select {
	case <-e.done:
	case <-time.After(10 * time.Second):
		t.Fatal("probe did not finish")
	}
	return e
}

func realityTestCacheSize(config *RealityConfig) int {
	cache := config.postHandshakeCache()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}

func toUint16s(lens []int) []uint16 {
	out := make([]uint16, 0, len(lens))
	for _, n := range lens {
		out = append(out, uint16(n))
	}
	return out
}

// Scenario A and B: the target sends records only after it received the
// client's Finished. The first REALITY connection (nothing learned yet) shows
// the mismatch; once the probe finished the REALITY server reproduces the
// target's record lengths.
func TestRealityPostHandshakeRecordsImitated(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), map[string][]int{"": {300, 150}}, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	want := realityTestObserveTarget(t, tt, nil, realityTestSuites)
	if len(want) != 2 {
		t.Fatalf("target after-Finished records = %v, want 2 records", want)
	}

	got, suite := realityTestConnect(t, addr, pub, nil, realityTestSuites)
	if len(got) != 0 {
		t.Fatalf("cold connection records = %v, want none (nothing learned yet)", got)
	}

	e := realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
	if !e.ok || !reflect.DeepEqual(e.lens, toUint16s(want)) {
		t.Fatalf("probe result ok=%v lens=%v, want %v", e.ok, e.lens, want)
	}

	for i := 0; i < 3; i++ {
		if got, _ := realityTestConnect(t, addr, pub, nil, realityTestSuites); !reflect.DeepEqual(got, want) {
			t.Fatalf("warm connection %d records = %v, want %v", i, got, want)
		}
	}
	if n := tt.completed.Load(); n != 2 { // the direct observation and exactly one probe
		t.Fatalf("target completed %d handshakes, want 2", n)
	}
}

// Scenario C: a target that sends nothing after its Finished.
func TestRealityPostHandshakeNoRecords(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), nil, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	if want := realityTestObserveTarget(t, tt, nil, realityTestSuites); len(want) != 0 {
		t.Fatalf("target after-Finished records = %v, want none", want)
	}
	got, suite := realityTestConnect(t, addr, pub, nil, realityTestSuites)
	if len(got) != 0 {
		t.Fatalf("cold connection records = %v, want none", got)
	}
	e := realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
	if !e.ok || len(e.lens) != 0 {
		t.Fatalf("probe result ok=%v lens=%v, want ok with no records", e.ok, e.lens)
	}
	if got, _ := realityTestConnect(t, addr, pub, nil, realityTestSuites); len(got) != 0 {
		t.Fatalf("warm connection records = %v, want none", got)
	}
}

// The probe must also work against a target that keeps the connection open:
// the collection window ends the probe.
func TestRealityPostHandshakeTargetKeepsOpen(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), map[string][]int{"": {777}}, false)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	want := realityTestObserveTarget(t, tt, nil, realityTestSuites)
	_, suite := realityTestConnect(t, addr, pub, nil, realityTestSuites)
	e := realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
	if !e.ok || !reflect.DeepEqual(e.lens, toUint16s(want)) {
		t.Fatalf("probe result ok=%v lens=%v, want %v", e.ok, e.lens, want)
	}
	if got, _ := realityTestConnect(t, addr, pub, nil, realityTestSuites); !reflect.DeepEqual(got, want) {
		t.Fatalf("warm connection records = %v, want %v", got, want)
	}
}

// Scenario D: the learned pattern is keyed by ALPN mode.
func TestRealityPostHandshakeALPN(t *testing.T) {
	post := map[string][]int{
		"":         {100},
		"http/1.1": {200},
		"h2":       {300, 400},
	}
	tt := newRealityTestTarget(t, realityTestTargetConfig([]string{"h2", "http/1.1"}, false), post, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	cases := []struct {
		name string
		alpn []string
	}{
		{"none", nil},
		{"http1", []string{"http/1.1"}},
		{"h2", []string{"h2", "http/1.1"}},
	}
	learned := map[string][]int{}
	for _, tc := range cases {
		want := realityTestObserveTarget(t, tt, tc.alpn, realityTestSuites)
		learned[tc.name] = want
		got, suite := realityTestConnect(t, addr, pub, tc.alpn, realityTestSuites)
		if len(got) != 0 {
			t.Fatalf("%s: cold connection records = %v, want none", tc.name, got)
		}
		e := realityTestWaitProbe(t, config, realityTestKey(config, tc.alpn, suite))
		if !e.ok || !reflect.DeepEqual(e.lens, toUint16s(want)) {
			t.Fatalf("%s: probe result ok=%v lens=%v, want %v", tc.name, e.ok, e.lens, want)
		}
		if got, _ := realityTestConnect(t, addr, pub, tc.alpn, realityTestSuites); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: warm connection records = %v, want %v", tc.name, got, want)
		}
	}
	if n := realityTestCacheSize(config); n != 3 {
		t.Fatalf("cache holds %d entries, want 3", n)
	}
	// The three modes must have produced different patterns, or the test
	// would not prove the keying.
	if reflect.DeepEqual(learned["none"], learned["http1"]) || reflect.DeepEqual(learned["http1"], learned["h2"]) {
		t.Fatalf("patterns are not distinct per ALPN mode: %v", learned)
	}
}

// A target that sends NewSessionTicket in its first flight (like Go servers)
// and more records after the client's Finished. The first-flight ticket is
// mirrored live and must not be imitated a second time.
func TestRealityPostHandshakeFirstFlightTicket(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, true), map[string][]int{"": {250}}, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	want := realityTestObserveTarget(t, tt, nil, realityTestSuites)
	if len(want) != 2 {
		t.Fatalf("target after-Finished records = %v, want ticket and one data record", want)
	}

	_, suite := realityTestConnect(t, addr, pub, nil, realityTestSuites)
	e := realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
	if !e.ok || !reflect.DeepEqual(e.lens, toUint16s(want)) {
		t.Fatalf("probe result ok=%v lens=%v, want %v", e.ok, e.lens, want)
	}
	for i := 0; i < 3; i++ {
		if got, _ := realityTestConnect(t, addr, pub, nil, realityTestSuites); !reflect.DeepEqual(got, want) {
			t.Fatalf("warm connection %d records = %v, want %v", i, got, want)
		}
	}
}

// Scenario E: many concurrent REALITY connections trigger exactly one probe.
func TestRealityPostHandshakeConcurrentProbe(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), map[string][]int{"": {512}}, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)
	want := realityTestObserveTarget(t, tt, nil, realityTestSuites)

	const n = 16
	var suite atomic.Uint32
	run := func(check func(got []int) error) {
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, s := realityTestConnect(t, addr, pub, nil, realityTestSuites)
				suite.Store(uint32(s))
				errs <- check(got)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	run(func(got []int) error {
		if len(got) != 0 && !reflect.DeepEqual(got, want) {
			return errors.New("unexpected records on a cold connection")
		}
		return nil
	})
	realityTestWaitProbe(t, config, realityTestKey(config, nil, uint16(suite.Load())))
	run(func(got []int) error {
		if !reflect.DeepEqual(got, want) {
			return errors.New("warm connection did not reproduce the target records")
		}
		return nil
	})
	if c := tt.completed.Load(); c != 2 { // the direct observation and a single probe
		t.Fatalf("target completed %d handshakes, want 2", c)
	}
	if c := tt.accepted.Load(); c != 2*n+2 {
		t.Fatalf("target accepted %d connections, want %d", c, 2*n+2)
	}
}

// Scenario F: a probe whose handshake is rejected does not affect service,
// is attempted once, and is retried only after the retry interval.
func TestRealityPostHandshakeProbeFailure(t *testing.T) {
	targetConfig := realityTestTargetConfig(nil, false)
	targetConfig.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		if len(chi.CipherSuites) == 1 { // only the probe pins a single suite
			return nil, errors.New("probe rejected")
		}
		return nil, nil
	}
	tt := newRealityTestTarget(t, targetConfig, map[string][]int{"": {128}}, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	var key realityPostHandshakeKey
	for i := 0; i < 4; i++ {
		got, suite := realityTestConnect(t, addr, pub, nil, realityTestSuites)
		if len(got) != 0 {
			t.Fatalf("connection %d records = %v, want none", i, got)
		}
		if i == 0 {
			key = realityTestKey(config, nil, suite)
			if e := realityTestWaitProbe(t, config, key); e.ok {
				t.Fatal("probe reported success although the target rejected it")
			}
		}
	}
	if c := tt.accepted.Load(); c != 4+1 {
		t.Fatalf("target accepted %d connections, want 4 live + 1 probe", c)
	}

	// Age the failure past the retry interval: the next connection probes again.
	cache := config.postHandshakeCache()
	cache.mu.Lock()
	cache.entries[key].finished = time.Now().Add(-2 * realityPostHandshakeRetryInterval)
	cache.mu.Unlock()
	if got, _ := realityTestConnect(t, addr, pub, nil, realityTestSuites); len(got) != 0 {
		t.Fatalf("records = %v, want none", got)
	}
	if e := realityTestWaitProbe(t, config, key); e.ok {
		t.Fatal("retried probe reported success although the target rejected it")
	}
	if c := tt.accepted.Load(); c != 5+2 {
		t.Fatalf("target accepted %d connections, want 7", c)
	}
}

// Scenario F: a probe that hangs times out without blocking service.
func TestRealityPostHandshakeProbeTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	targetConfig := realityTestTargetConfig(nil, false)
	targetConfig.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		if len(chi.CipherSuites) == 1 {
			<-release
			return nil, errors.New("probe rejected")
		}
		return nil, nil
	}
	tt := newRealityTestTarget(t, targetConfig, nil, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	start := time.Now()
	var suite uint16
	for i := 0; i < 3; i++ {
		got, s := realityTestConnect(t, addr, pub, nil, realityTestSuites)
		if len(got) != 0 {
			t.Fatalf("connection %d records = %v, want none", i, got)
		}
		suite = s
	}
	if d := time.Since(start); d > realityPostHandshakeProbeTimeout {
		t.Fatalf("connections took %v; the hanging probe blocked them", d)
	}
	e := realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
	if e.ok {
		t.Fatal("hanging probe reported success")
	}
	if got, _ := realityTestConnect(t, addr, pub, nil, realityTestSuites); len(got) != 0 {
		t.Fatalf("records after probe timeout = %v, want none", got)
	}
}

// Scenario G: clones share the probe state of the original config.
func TestRealityConfigCloneSharesProbeCache(t *testing.T) {
	if zero := (&RealityConfig{}).Clone(); zero.postHandshake.Load() == nil {
		t.Fatal("clone of a zero config did not initialise the shared cache")
	}

	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), map[string][]int{"": {333}}, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	clone := config.Clone()
	if clone.postHandshakeCache() != config.postHandshakeCache() {
		t.Fatal("clone does not share the probe cache")
	}
	if clone.Clone().postHandshakeCache() != config.postHandshakeCache() {
		t.Fatal("clone of a clone does not share the probe cache")
	}

	want := realityTestObserveTarget(t, tt, nil, realityTestSuites)
	viaClone := newRealityTestServer(t, clone)
	viaOriginal := newRealityTestServer(t, config)

	_, suite := realityTestConnect(t, viaClone, pub, nil, realityTestSuites)
	realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
	if got, _ := realityTestConnect(t, viaOriginal, pub, nil, realityTestSuites); !reflect.DeepEqual(got, want) {
		t.Fatalf("original config records = %v, want %v", got, want)
	}
	if got, _ := realityTestConnect(t, viaClone, pub, nil, realityTestSuites); !reflect.DeepEqual(got, want) {
		t.Fatalf("clone config records = %v, want %v", got, want)
	}
	if c := tt.completed.Load(); c != 2 {
		t.Fatalf("target completed %d handshakes, want the observation and one shared probe", c)
	}
}

// The negotiated cipher suite is part of the key, and the probe pins it.
func TestRealityPostHandshakeCipherSuiteKey(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), map[string][]int{"": {64}}, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)

	for _, suite := range []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384} {
		want := realityTestObserveTarget(t, tt, nil, []uint16{suite})
		if _, negotiated := realityTestConnect(t, addr, pub, nil, []uint16{suite}); negotiated != suite {
			t.Fatalf("negotiated %x, want %x", negotiated, suite)
		}
		e := realityTestWaitProbe(t, config, realityTestKey(config, nil, suite))
		if !e.ok || !reflect.DeepEqual(e.lens, toUint16s(want)) {
			t.Fatalf("suite %x: probe result ok=%v lens=%v, want %v", suite, e.ok, e.lens, want)
		}
		if got, _ := realityTestConnect(t, addr, pub, nil, []uint16{suite}); !reflect.DeepEqual(got, want) {
			t.Fatalf("suite %x: warm connection records = %v, want %v", suite, got, want)
		}
	}
	if n := realityTestCacheSize(config); n != 2 {
		t.Fatalf("cache holds %d entries, want one per suite", n)
	}
}

func TestRealityParsePostHandshakeRecords(t *testing.T) {
	record := func(typ byte, payload int) []byte {
		b := []byte{typ, 3, 3, byte(payload >> 8), byte(payload)}
		return append(b, make([]byte, payload)...)
	}
	cat := func(parts ...[]byte) (out []byte) {
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	cases := []struct {
		name string
		data []byte
		want []uint16
		ok   bool
	}{
		{"empty", nil, []uint16{}, true},
		{"one", record(23, 100), []uint16{105}, true},
		{"two", cat(record(23, 17), record(23, 16384+17)), []uint16{22, 16406}, true},
		{"too short", record(23, 16), nil, false},
		{"too long", record(23, 16384+18), nil, false},
		{"handshake type", record(22, 100), nil, false},
		{"alert type", record(21, 2), nil, false},
		{"bad version", []byte{23, 3, 4, 0, 20, 0}, nil, false},
		{"cut header", []byte{23, 3, 3, 0}, nil, false},
		{"cut body", record(23, 100)[:50], nil, false},
		{"trailing garbage", cat(record(23, 100), []byte{23, 3}), nil, false},
		{"too many", cat(record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20)), nil, false},
		{"at limit", cat(record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20), record(23, 20)), []uint16{25, 25, 25, 25, 25, 25, 25, 25}, true},
	}
	for _, tc := range cases {
		got, ok := realityParsePostHandshakeRecords(tc.data)
		if ok != tc.ok || (ok && !reflect.DeepEqual(got, tc.want)) {
			t.Errorf("%s: got %v ok=%v, want %v ok=%v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRealityALPNMode(t *testing.T) {
	cases := []struct {
		protos []string
		want   uint8
	}{
		{nil, realityALPNNone},
		{[]string{}, realityALPNNone},
		{[]string{"http/1.1"}, realityALPNHTTP1},
		{[]string{"h2"}, realityALPNH2},
		{[]string{"h2", "http/1.1"}, realityALPNH2},
		{[]string{"http/1.1", "h2"}, realityALPNH2},
		{[]string{"foo"}, realityALPNHTTP1},
	}
	for _, tc := range cases {
		if got := realityALPNMode(tc.protos); got != tc.want {
			t.Errorf("realityALPNMode(%v) = %d, want %d", tc.protos, got, tc.want)
		}
	}
}

// Writing an imitation record must leave the sequence numbers consistent so
// that later application data still decrypts; the end-to-end tests above rely
// on the marker for that. This checks the length and validation directly.
func TestRealityWritePostHandshakeRecordLength(t *testing.T) {
	server, client := localPipe(t)
	defer server.Close()
	defer client.Close()

	serverConfig := realityTestTargetConfig(nil, false)
	done := make(chan error, 1)
	go func() {
		c := Client(client, &Config{ServerName: realityTestServerName, InsecureSkipVerify: true, MinVersion: VersionTLS13})
		if err := c.Handshake(); err != nil {
			done <- err
			return
		}
		buf := make([]byte, len(realityTestMarker))
		_, err := io.ReadFull(c, buf)
		done <- err
	}()

	countingConn := &countingWriter{Conn: server}
	s := Server(countingConn, serverConfig)
	if err := s.Handshake(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int{0, 21, realityMaxPostHandshakeRecordLen + 1} {
		if err := s.realityWritePostHandshakeRecord(bad); err == nil {
			t.Fatalf("length %d accepted", bad)
		}
	}
	for _, length := range []int{realityMinPostHandshakeRecordLen, 123, realityMaxPostHandshakeRecordLen} {
		countingConn.n = 0
		if err := s.realityWritePostHandshakeRecord(length); err != nil {
			t.Fatal(err)
		}
		if countingConn.n != length {
			t.Fatalf("wrote %d bytes, want %d", countingConn.n, length)
		}
	}
	if _, err := s.Write(realityTestMarker); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("client failed after imitation records: %v", err)
	}
}

type countingWriter struct {
	net.Conn
	n int
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.n += n
	return n, err
}
