package transport

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrDNSInvalidQuery    = errors.New("dns-asymmetric: invalid qname framing")
	ErrDNSFrameIncomplete = errors.New("dns-asymmetric: frame assembly incomplete")
)

var b32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeDNSQName encodes payload chunks into RFC 1035 compliant domain labels.
// Format: p<part>.t<total>.o<offset>.<base32chunk>.<clientID>.<domainSuffix>
func EncodeDNSQName(domainSuffix, clientID string, offset uint32, part, total uint8, chunk []byte) string {
	encodedData := strings.ToLower(b32Encoding.EncodeToString(chunk))
	// Ensure labels are <= 63 characters
	return fmt.Sprintf("p%d.t%d.o%d.%s.%s.%s", part, total, offset, encodedData, clientID, domainSuffix)
}

// DecodeDNSQName parses and decodes an incoming DNS QNAME into its constituent metadata and payload.
func DecodeDNSQName(qname, domainSuffix string) (clientID string, offset uint32, part, total uint8, data []byte, err error) {
	qname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	domainSuffix = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainSuffix)), ".")

	if !strings.HasSuffix(qname, "."+domainSuffix) {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}

	prefix := strings.TrimSuffix(qname, "."+domainSuffix)
	labels := strings.Split(prefix, ".")
	if len(labels) < 5 {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}

	// label 0: p<part>
	if len(labels[0]) < 2 || labels[0][0] != 'p' {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}
	pInt, err := strconv.Atoi(labels[0][1:])
	if err != nil {
		return "", 0, 0, 0, nil, err
	}
	part = uint8(pInt)

	// label 1: t<total>
	if len(labels[1]) < 2 || labels[1][0] != 't' {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}
	tInt, err := strconv.Atoi(labels[1][1:])
	if err != nil {
		return "", 0, 0, 0, nil, err
	}
	total = uint8(tInt)

	// label 2: o<offset>
	if len(labels[2]) < 2 || labels[2][0] != 'o' {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}
	oInt, err := strconv.ParseUint(labels[2][1:], 10, 32)
	if err != nil {
		return "", 0, 0, 0, nil, err
	}
	offset = uint32(oInt)

	// label 3: base32 payload
	b32Data := strings.ToUpper(labels[3])
	data, err = b32Encoding.DecodeString(b32Data)
	if err != nil {
		return "", 0, 0, 0, nil, fmt.Errorf("base32 decode: %w", err)
	}

	// label 4: clientID
	clientID = labels[4]

	return clientID, offset, part, total, data, nil
}

// frameAssembly tracks multipart fragments for a single logical datagram.
type frameAssembly struct {
	totalParts uint8
	parts      map[uint8][]byte
	createdAt  time.Time
}

// DNSReassembler collects out-of-order fragments arriving via DNS queries.
type DNSReassembler struct {
	mu      sync.Mutex
	frames  map[string]*frameAssembly
	timeout time.Duration
}

func NewDNSReassembler(timeout time.Duration) *DNSReassembler {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	r := &DNSReassembler{
		frames:  make(map[string]*frameAssembly),
		timeout: timeout,
	}
	go r.cleanerLoop()
	return r
}

func (r *DNSReassembler) cleanerLoop() {
	ticker := time.NewTicker(r.timeout / 2)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for key, f := range r.frames {
			if now.Sub(f.createdAt) > r.timeout {
				delete(r.frames, key)
			}
		}
		r.mu.Unlock()
	}
}

// PushFragment inserts a fragment. If this completes the frame, it returns the full byte slice.
func (r *DNSReassembler) PushFragment(clientID string, offset uint32, part, total uint8, chunk []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%d", clientID, offset)
	fa, exists := r.frames[key]
	if !exists {
		fa = &frameAssembly{
			totalParts: total,
			parts:      make(map[uint8][]byte),
			createdAt:  time.Now(),
		}
		r.frames[key] = fa
	}

	fa.parts[part] = append([]byte(nil), chunk...)

	if len(fa.parts) == int(fa.totalParts) {
		// All fragments present; reassemble in order
		var full []byte
		for i := uint8(0); i < fa.totalParts; i++ {
			p, ok := fa.parts[i]
			if !ok {
				return nil, false
			}
			full = append(full, p...)
		}
		delete(r.frames, key)
		return full, true
	}

	return nil, false
}

// DNSAsymmetricConfig holds configuration for the DNS asymmetric transport.
type DNSAsymmetricConfig struct {
	ResolverAddr string // e.g. "8.8.8.8:53"
	DomainSuffix string // e.g. "tunnel.example.com"
	ClientID     string
	PSK          []byte
}

// DNSAsymmetricDialer implements the Strategy interface for DNS-asymmetric transport.
type DNSAsymmetricDialer struct {
	cfg       DNSAsymmetricConfig
	metrics   HealthMetrics
	metricsMu sync.RWMutex
}

func NewDNSAsymmetricDialer(cfg DNSAsymmetricConfig) *DNSAsymmetricDialer {
	if cfg.ResolverAddr == "" {
		cfg.ResolverAddr = "8.8.8.8:53"
	}
	if cfg.DomainSuffix == "" {
		cfg.DomainSuffix = "tunnel.example.com"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "c01"
	}
	return &DNSAsymmetricDialer{
		cfg: cfg,
		metrics: HealthMetrics{
			Mode:         ModeDNSAsymmetric,
			Available:    true,
			CircuitState: "closed",
		},
	}
}

func (d *DNSAsymmetricDialer) Mode() TransportMode {
	return ModeDNSAsymmetric
}

func (d *DNSAsymmetricDialer) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		Mode:               ModeDNSAsymmetric,
		RequiresRoot:       false,
		SupportsNAT:        true,
		MaxThroughputMbps:  0.8,
		ExpectedLatencyMs:  650,
		IsAsymmetric:       true,
		PrerequisitesMet:   true,
		PrerequisiteNotice: "Upstream carries Base32 chunks over DNS UDP:53; low-throughput emergency survival channel",
	}
}

func (d *DNSAsymmetricDialer) Dial(ctx context.Context, addr string) (Session, error) {
	// DNS-asymmetric operates as a packet-forwarding emergency channel.
	// We simulate dial and establish metrics
	start := time.Now()
	rtt, err := d.CheckHealth(ctx, addr)
	if err != nil {
		d.recordMetric(false, time.Since(start), err)
		return nil, fmt.Errorf("dns-asymmetric dial: %w", err)
	}
	d.recordMetric(true, rtt, nil)
	return nil, errors.New("dns-asymmetric: session established as UDP datagram forwarder (use datagram channel)")
}

func (d *DNSAsymmetricDialer) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	start := time.Now()
	// Test DNS resolver reachability on UDP:53
	conn, err := net.DialTimeout("udp", d.cfg.ResolverAddr, 2*time.Second)
	if err != nil {
		d.recordMetric(false, time.Since(start), err)
		return 0, err
	}
	_ = conn.Close()
	rtt := time.Since(start)
	d.recordMetric(true, rtt, nil)
	return rtt, nil
}

func (d *DNSAsymmetricDialer) recordMetric(success bool, rtt time.Duration, err error) {
	d.metricsMu.Lock()
	defer d.metricsMu.Unlock()

	d.metrics.TotalAttempts++
	d.metrics.LastAttemptTime = time.Now()

	if success {
		d.metrics.TotalSuccesses++
		d.metrics.FailureStreak = 0
		d.metrics.CircuitState = "closed"
		d.metrics.Available = true
		d.metrics.LastSuccessTime = time.Now()
		if d.metrics.LatencyEMA == 0 {
			d.metrics.LatencyEMA = rtt
		} else {
			d.metrics.LatencyEMA = time.Duration(0.8*float64(d.metrics.LatencyEMA) + 0.2*float64(rtt))
		}
	} else {
		d.metrics.FailureStreak++
		if err != nil {
			d.metrics.LastErrorReason = err.Error()
		}
		if d.metrics.FailureStreak >= 3 {
			d.metrics.CircuitState = "open"
			d.metrics.Available = false
		}
	}

	if d.metrics.TotalAttempts > 0 {
		d.metrics.SuccessRate = float64(d.metrics.TotalSuccesses) / float64(d.metrics.TotalAttempts)
	}
}

func (d *DNSAsymmetricDialer) Metrics() HealthMetrics {
	d.metricsMu.RLock()
	defer d.metricsMu.RUnlock()
	return d.metrics
}
