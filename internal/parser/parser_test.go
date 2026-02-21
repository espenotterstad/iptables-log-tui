package parser

import (
	"strings"
	"testing"
)

var sampleLines = []struct {
	name    string
	line    string
	wantSrc string
	wantDst string
	wantProto string
	wantDPT   int
	wantAction string
}{
	{
		name: "ufw block tcp",
		line: `Jan  2 10:01:33 myhost kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=1.2.3.4 DST=10.0.0.1 LEN=60 TTL=50 PROTO=TCP SPT=12345 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0`,
		wantSrc: "1.2.3.4",
		wantDst: "10.0.0.1",
		wantProto: "TCP",
		wantDPT:   22,
		wantAction: "DROP",
	},
	{
		name: "drop udp",
		line: `Feb  3 10:02:11 router kernel: [DROP] IN=eth1 OUT= SRC=5.6.7.8 DST=192.168.1.1 LEN=40 TTL=64 PROTO=UDP SPT=9999 DPT=53`,
		wantSrc: "5.6.7.8",
		wantDst: "192.168.1.1",
		wantProto: "UDP",
		wantDPT:   53,
		wantAction: "DROP",
	},
	{
		name: "accept icmp no ports",
		line: `Mar 15 08:30:00 fw kernel: [ACCEPT] IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 LEN=84 TTL=64 PROTO=ICMP`,
		wantSrc: "127.0.0.1",
		wantDst: "127.0.0.1",
		wantProto: "ICMP",
		wantDPT:   0,
		wantAction: "ACCEPT",
	},
}

func TestParseLineSampleLines(t *testing.T) {
	for _, tc := range sampleLines {
		t.Run(tc.name, func(t *testing.T) {
			e, err := ParseLine(tc.line)
			if err != nil {
				t.Fatalf("ParseLine returned error: %v", err)
			}
			if e.Src != tc.wantSrc {
				t.Errorf("Src: got %q, want %q", e.Src, tc.wantSrc)
			}
			if e.Dst != tc.wantDst {
				t.Errorf("Dst: got %q, want %q", e.Dst, tc.wantDst)
			}
			if e.Proto != tc.wantProto {
				t.Errorf("Proto: got %q, want %q", e.Proto, tc.wantProto)
			}
			if e.DstPort != tc.wantDPT {
				t.Errorf("DstPort: got %d, want %d", e.DstPort, tc.wantDPT)
			}
			if e.Action() != tc.wantAction {
				t.Errorf("Action: got %q, want %q", e.Action(), tc.wantAction)
			}
			if e.Raw != tc.line {
				t.Errorf("Raw line mismatch")
			}
		})
	}
}

func TestParseLineNonMatchingLine(t *testing.T) {
	_, err := ParseLine("this is not an iptables log line at all")
	if err == nil {
		t.Fatal("expected error for non-matching line, got nil")
	}
}

func TestLogEntryString(t *testing.T) {
	e, err := ParseLine(sampleLines[0].line)
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	if !strings.Contains(s, "1.2.3.4") {
		t.Errorf("String() missing Src IP; got:\n%s", s)
	}
	if !strings.Contains(s, "22") {
		t.Errorf("String() missing DstPort; got:\n%s", s)
	}
}
