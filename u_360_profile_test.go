package tls

import (
	"net"
	"reflect"
	"testing"
)

func Test360Chrome23ClientHello(t *testing.T) {
	conn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, Hello360_Auto)
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := conn.HandshakeState.Hello
	shares := hello.KeyShares
	if len(shares) != 3 || !isGREASEUint16(uint16(shares[0].Group)) ||
		shares[1].Group != X25519MLKEM768 || len(shares[1].Data) != 1216 ||
		shares[2].Group != X25519 || len(shares[2].Data) != 32 {
		t.Fatal("unexpected key shares")
	}
	wantVersions := []uint16{VersionTLS13, VersionTLS12, VersionTLS11, VersionTLS10}
	if len(hello.SupportedVersions) != len(wantVersions)+1 ||
		!isGREASEUint16(hello.SupportedVersions[0]) || !reflect.DeepEqual(hello.SupportedVersions[1:], wantVersions) {
		t.Fatalf("unexpected supported versions: %x", hello.SupportedVersions)
	}
	for _, ext := range conn.Extensions {
		if alps, ok := ext.(*ApplicationSettingsExtension); ok && reflect.DeepEqual(alps.SupportedProtocols, []string{"h2"}) {
			return
		}
	}
	t.Fatal("missing old ALPS codepoint for h2")
}
