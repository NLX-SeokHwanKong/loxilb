package options

import (
	"github.com/jessevdk/go-flags"
	"testing"
)

func TestTCPReturnVIPs(t *testing.T) {
	for _, value := range []string{"", "::ffff:192.0.2.1", "::1", "192.0.2.0/24", "0.0.0.0", "224.0.0.1", "255.255.255.255", "example.org", "127.0.0.1"} {
		var v TCPReturnVIP
		if err := v.UnmarshalFlag(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	var cfg struct {
		VIPs []TCPReturnVIP `long:"tcp-return-vip"`
	}
	parser := flags.NewParser(&cfg, flags.None)
	if _, err := parser.ParseArgs(nil); err != nil || len(cfg.VIPs) != 0 {
		t.Fatal("not disabled by default", err)
	}
	if _, err := parser.ParseArgs([]string{"--tcp-return-vip=192.0.2.1", "--tcp-return-vip=192.0.2.2"}); err != nil || len(cfg.VIPs) != 2 || cfg.VIPs[1] != "192.0.2.2" {
		t.Fatal(cfg, err)
	}
}
