package audit

import "testing"

func TestIsRemoteCDPURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "loopback url", url: "http://127.0.0.1:9222", want: false},
		{name: "localhost ws", url: "ws://localhost:9222/devtools/browser", want: false},
		{name: "remote ws", url: "wss://cdp.example.com/devtools/browser", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isRemoteCDPURL(test.url); got != test.want {
				t.Fatalf("isRemoteCDPURL(%q)=%v, want %v", test.url, got, test.want)
			}
		})
	}
}
