package tls

import (
	"net"
	"testing"
)

func TestSafariKeyShares(t *testing.T) {
	for _, tc := range []struct {
		id         ClientHelloID
		wantHybrid bool
	}{
		{HelloSafari_Auto, true},
		{HelloSafari_16_0, false},
	} {
		conn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, tc.id)
		if err := conn.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		shares := conn.HandshakeState.Hello.KeyShares
		var groups []CurveID
		for _, share := range shares {
			if !isGREASEUint16(uint16(share.Group)) {
				groups = append(groups, share.Group)
			}
		}
		if tc.wantHybrid {
			if len(groups) < 2 || groups[0] != X25519MLKEM768 || groups[1] != X25519 {
				t.Fatalf("%s: unexpected key shares %v", tc.id.Str(), groups)
			}
		} else {
			for _, group := range groups {
				if group == X25519MLKEM768 {
					t.Fatalf("%s: legacy profile gained a hybrid key share", tc.id.Str())
				}
			}
		}
	}
}
