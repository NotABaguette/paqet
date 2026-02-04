package conf

import (
	"fmt"
	"slices"
)

type TCP struct {
	LF_     []string `yaml:"local_flag"`
	RF_     []string `yaml:"remote_flag"`
	SeqMode string   `yaml:"seq_mode"`
	LF      []TCPF   `yaml:"-"`
	RF      []TCPF   `yaml:"-"`
}

type TCPF struct {
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
}

func (t *TCP) setDefaults() {
	if len(t.LF_) == 0 {
		t.LF_ = []string{"PA"}
	}
	if len(t.RF_) == 0 {
		t.RF_ = []string{"PA"}
	}
	if t.SeqMode == "" {
		t.SeqMode = "legacy"
	}
}

func (t *TCP) validate() []error {
	var errors []error

	if len(t.LF_) != 0 {
		t.LF = make([]TCPF, len(t.LF_))
		for i, fStr := range t.LF_ {
			f, err := strTCPF(fStr)
			if err != nil {
				errors = append(errors, err)
			}
			t.LF[i] = f
		}
	}
	if len(t.RF_) != 0 {
		t.RF = make([]TCPF, len(t.RF_))
		for i, fStr := range t.RF_ {
			f, err := strTCPF(fStr)
			if err != nil {
				errors = append(errors, err)
			}
			t.RF[i] = f
		}
	}

	if len(t.LF) == 0 || len(t.RF) == 0 {
		errors = append(errors, fmt.Errorf("at least one TCP flag combination required"))
	}
	validSeqModes := []string{"legacy", "monotonic"}
	if !slices.Contains(validSeqModes, t.SeqMode) {
		errors = append(errors, fmt.Errorf("TCP seq_mode must be one of: %v", validSeqModes))
	}
	return errors
}

func strTCPF(fStr string) (TCPF, error) {
	var f TCPF
	for _, ch := range fStr {
		switch ch {
		case 'F':
			f.FIN = true
		case 'S':
			f.SYN = true
		case 'R':
			f.RST = true
		case 'P':
			f.PSH = true
		case 'A':
			f.ACK = true
		case 'U':
			f.URG = true
		case 'E':
			f.ECE = true
		case 'C':
			f.CWR = true
		case 'N':
			f.NS = true
		default:
			return f, fmt.Errorf("invalid TCP flag '%c' in combination", ch)
		}
	}
	return f, nil
}
