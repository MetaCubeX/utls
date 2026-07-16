package tls

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/utls/internal/circl/sign/mldsa/mldsa65"
)

func TestRealityServerWritesProxyProtocolHeader(t *testing.T) {
	for _, version := range []byte{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			client, rawServer := net.Pipe()
			server := &realityAddrConn{
				Conn:       rawServer,
				localAddr:  &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443},
				remoteAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 12345},
			}
			targetServer, targetClient := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
				_ = targetServer.Close()
				_ = targetClient.Close()
			})
			result := make(chan error, 1)
			go func() {
				_, err := RealityServer(context.Background(), server, &RealityConfig{
					DialContext: func(context.Context, string, string) (net.Conn, error) { return targetServer, nil },
					Xver:        version,
				})
				result <- err
			}()

			_ = targetClient.SetReadDeadline(time.Now().Add(time.Second))
			if version == 1 {
				line, err := bufio.NewReader(targetClient).ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				want := "PROXY TCP4 198.51.100.20 192.0.2.10 12345 443\r\n"
				if line != want {
					t.Fatalf("header = %q, want %q", line, want)
				}
			} else {
				header := make([]byte, 28)
				if _, err := io.ReadFull(targetClient, header); err != nil {
					t.Fatal(err)
				}
				if got := string(header[:12]); got != "\r\n\r\n\x00\r\nQUIT\n" {
					t.Fatalf("v2 signature = %q", got)
				}
				if header[12] != 0x21 || header[13] != 0x11 || header[14] != 0 || header[15] != 12 {
					t.Fatalf("v2 prefix = %x", header[:16])
				}
			}
			_ = client.Close()
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Fatal("RealityServer did not stop")
			}
		})
	}
}

func TestRealityMldsa65Helpers(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey, publicKey, err := RealityMldsa65KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey) != 4032 || len(publicKey) != 1952 {
		t.Fatalf("key lengths = %d/%d, want 4032/1952", len(privateKey), len(publicKey))
	}
	message := []byte("xray REALITY transcript")
	key := new(mldsa65.PrivateKey)
	if err := key.UnmarshalBinary(privateKey); err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 3309)
	if err := mldsa65.SignTo(key, message, nil, false, signature); err != nil {
		t.Fatal(err)
	}
	if !RealityMldsa65Verify(publicKey, message, signature) {
		t.Fatal("RealityMldsa65Verify() = false")
	}
	signature[len(signature)-1] ^= 1
	if RealityMldsa65Verify(publicKey, message, signature) {
		t.Fatal("RealityMldsa65Verify() accepted modified signature")
	}
	if _, _, err := RealityMldsa65KeyFromSeed([]byte(strings.Repeat("x", 31))); err == nil {
		t.Fatal("RealityMldsa65KeyFromSeed() accepted a short seed")
	}
}

func TestRealityCloseWritePreservesReadSide(t *testing.T) {
	conn := newRealityCloseWriteRecorder()
	defer conn.Conn.Close()
	if err := realityCloseWrite(conn); err != nil {
		t.Fatal(err)
	}
	if !conn.closeWriteCalled {
		t.Fatal("CloseWrite was not called")
	}
	if conn.closeCalled {
		t.Fatal("Close was called for a half-close capable connection")
	}

	plainClient, plainServer := net.Pipe()
	if err := realityCloseWrite(plainServer); err != nil {
		t.Fatal(err)
	}
	if _, err := plainClient.Write([]byte("closed")); err == nil {
		t.Fatal("fallback connection without CloseWrite remained open")
	}
	_ = plainClient.Close()
}

type realityCloseWriteRecorder struct {
	net.Conn
	closeWriteCalled bool
	closeCalled      bool
}

func newRealityCloseWriteRecorder() *realityCloseWriteRecorder {
	left, right := net.Pipe()
	_ = right.Close()
	return &realityCloseWriteRecorder{Conn: left}
}

func (c *realityCloseWriteRecorder) CloseWrite() error {
	c.closeWriteCalled = true
	return nil
}

func (c *realityCloseWriteRecorder) Close() error {
	c.closeCalled = true
	return c.Conn.Close()
}

type realityAddrConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *realityAddrConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *realityAddrConn) RemoteAddr() net.Addr { return c.remoteAddr }
