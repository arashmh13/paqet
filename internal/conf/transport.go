package conf

import (
	"fmt"
	"slices"
)

type Transport struct {
	Protocol string `yaml:"protocol"`
	Conn     int    `yaml:"conn"`
	KCP      *KCP   `yaml:"kcp"`
	Obfs     *Obfs  `yaml:"obfs"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}

	var kcpKey string
	switch t.Protocol {
	case "kcp":
		if t.KCP != nil {
			t.KCP.setDefaults(role)
			kcpKey = t.KCP.Key
		}
	}

	if t.Obfs == nil {
		t.Obfs = &Obfs{}
	}
	t.Obfs.setDefaults(kcpKey)
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{"kcp", "stream"}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("transport conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp":
		if t.KCP == nil {
			errors = append(errors, fmt.Errorf("transport.kcp configuration is required"))
		} else {
			errors = append(errors, t.KCP.validate()...)
		}
	case "stream":
		if t.Obfs == nil || len(t.Obfs.Key) == 0 {
			errors = append(errors, fmt.Errorf("transport.obfs.key is required for stream protocol"))
		}
	}

	if t.Obfs != nil {
		mtu := 0
		if t.KCP != nil {
			mtu = t.KCP.MTU
		}
		errors = append(errors, t.Obfs.validate(mtu)...)
	}

	return errors
}
