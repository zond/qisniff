package sum

import "testing"

func TestSum(t *testing.T) {
	if tcpipChecksum([]byte("0123456789012"), 0) != 50328 {
		t.Errorf("Wrong checksum!")
	}
}
