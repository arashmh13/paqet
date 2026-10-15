package conf

import (
	"fmt"
	"slices"
)

type SNI struct {
	Decoy  string `yaml:"decoy"`
	Preset string `yaml:"preset"`
	Method string `yaml:"method"`
}

type DNS struct {
	Resolver     string `yaml:"resolver"`
	DomainSuffix string `yaml:"domain_suffix"`
	ClientID     string `yaml:"client_id"`
}

type Spoof struct {
	SpoofIP         string `yaml:"spoof_ip"`
	AllowUnverified bool   `yaml:"allow_unverified"`
}

type Selector struct {
	StrategyOrder   []string `yaml:"strategy_order"`
	CooldownSec     int      `yaml:"cooldown_sec"`
	HysteresisRatio float64  `yaml:"hysteresis_ratio"`
}

type Transport struct {
	Protocol string    `yaml:"protocol"`
	Conn     int       `yaml:"conn"`
	KCP      *KCP      `yaml:"kcp"`
	Obfs     *Obfs     `yaml:"obfs"`
	SNI      *SNI      `yaml:"sni"`
	DNS      *DNS      `yaml:"dns"`
	Spoof    *Spoof    `yaml:"spoof"`
	Selector *Selector `yaml:"selector"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}

	var kcpKey string
	switch t.Protocol {
	case "kcp", "raw-kcp":
		if t.KCP != nil {
			t.KCP.setDefaults(role)
			kcpKey = t.KCP.Key
		}
	}

	if t.Obfs == nil {
		t.Obfs = &Obfs{}
	}
	t.Obfs.setDefaults(kcpKey)

	if t.SNI == nil {
		t.SNI = &SNI{
			Decoy:  "hcaptcha.com",
			Preset: "chrome",
			Method: "wrong_seq",
		}
	}
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{
		"kcp", "raw-kcp",
		"stream", "aead-stream",
		"sni-assisted",
		"asymmetric-spoof",
		"dns-asymmetric",
		"auto",
	}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("transport conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp", "raw-kcp":
		if t.KCP == nil {
			errors = append(errors, fmt.Errorf("transport.kcp configuration is required"))
		} else {
			errors = append(errors, t.KCP.validate()...)
		}
	case "stream", "aead-stream", "sni-assisted", "auto":
		if t.Obfs == nil || len(t.Obfs.Key) == 0 {
			errors = append(errors, fmt.Errorf("transport.obfs.key is required for %s protocol", t.Protocol))
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
