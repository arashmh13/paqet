package transport

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"paqet/internal/ng/dns"
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
	if total == 0 || total > 64 || part >= total {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}

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

// MaxPendingFrames limits pending reassembly sessions to prevent RAM exhaustion.
const MaxPendingFrames = 1024

// PushFragment inserts a fragment. If this completes the frame, it returns the full byte slice.
func (r *DNSReassembler) PushFragment(clientID string, offset uint32, part, total uint8, chunk []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%d", clientID, offset)
	fa, exists := r.frames[key]
	if !exists {
		if len(r.frames) >= MaxPendingFrames {
			return nil, false // Protect memory against fragment flood attacks
		}
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
	ResolverAddr string   // Primary resolver (e.g. "8.8.8.8:53")
	ResolverPool []string // Optional candidate pool for dynamic resolver discovery & scoring
	DomainSuffix string   // e.g. "tunnel.example.com"
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

// SelectBestResolver probes the candidate resolver pool using clean-room multi-factor scoring
// and selects the highest-scoring, lowest-latency unpoisoned resolver.
func (d *DNSAsymmetricDialer) SelectBestResolver(ctx context.Context) string {
	d.metricsMu.RLock()
	pool := make([]string, len(d.cfg.ResolverPool))
	copy(pool, d.cfg.ResolverPool)
	current := d.cfg.ResolverAddr
	suffix := d.cfg.DomainSuffix
	d.metricsMu.RUnlock()

	if len(pool) == 0 {
		return current
	}

	results := dns.ScanResolverPool(ctx, pool, 53, suffix, 2*time.Second, 4)
	if len(results) > 0 && results[0].Score >= 4 {
		best := net.JoinHostPort(results[0].Host, fmt.Sprintf("%d", results[0].Port))
		d.metricsMu.Lock()
		d.cfg.ResolverAddr = best
		d.metricsMu.Unlock()
		return best
	}

	return current
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

// BuildDNSQuery constructs an RFC 1035 compliant UDP DNS Query packet.
func BuildDNSQuery(qname string, qtype uint16, id uint16) []byte {
	var buf []byte

	// 12-byte DNS Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Standard query, recursion desired
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT = 1
	buf = append(buf, header...)

	// QNAME: series of length-prefixed labels
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	for _, l := range labels {
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0x00) // Root label null terminator

	// QTYPE and QCLASS
	trailer := make([]byte, 4)
	binary.BigEndian.PutUint16(trailer[0:2], qtype)
	binary.BigEndian.PutUint16(trailer[2:4], 0x0001) // Class IN
	buf = append(buf, trailer...)

	return buf
}

// ParseDNSQuery extracts QNAME, QTYPE, and transaction ID from an incoming wire DNS query.
func ParseDNSQuery(packet []byte) (id uint16, qname string, qtype uint16, err error) {
	if len(packet) < 16 {
		return 0, "", 0, ErrDNSInvalidQuery
	}

	id = binary.BigEndian.Uint16(packet[0:2])
	offset := 12

	var labels []string
	for offset < len(packet) {
		length := int(packet[offset])
		offset++
		if length == 0 {
			break // Root label
		}
		if offset+length > len(packet) {
			return 0, "", 0, ErrDNSInvalidQuery
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(packet) {
		return 0, "", 0, ErrDNSInvalidQuery
	}
	qtype = binary.BigEndian.Uint16(packet[offset : offset+2])
	qname = strings.Join(labels, ".")

	return id, qname, qtype, nil
}

// BuildDNSTXTResponse constructs an RFC 1035 DNS response with a TXT answer record.
func BuildDNSTXTResponse(reqPacket []byte, txtPayload []byte) ([]byte, error) {
	if len(reqPacket) < 12 {
		return nil, ErrDNSInvalidQuery
	}

	id := binary.BigEndian.Uint16(reqPacket[0:2])

	// Find end of Question section
	offset := 12
	for offset < len(reqPacket) {
		length := int(reqPacket[offset])
		offset++
		if length == 0 {
			break
		}
		offset += length
	}
	offset += 4 // QTYPE + QCLASS
	if offset > len(reqPacket) {
		return nil, ErrDNSInvalidQuery
	}

	questionSec := reqPacket[12:offset]

	var resp []byte
	// Header (12 bytes)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // QR=1, AA=1, RD=1, RA=1 (Standard response)
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT = 1
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT = 1
	resp = append(resp, hdr...)
	resp = append(resp, questionSec...)

	// Answer Section: Name pointer pointing to Question QNAME at offset 12 (0xC00C)
	ansHdr := make([]byte, 10)
	binary.BigEndian.PutUint16(ansHdr[0:2], 0xC00C) // Pointer to QNAME
	binary.BigEndian.PutUint16(ansHdr[2:4], 0x0010) // TYPE TXT
	binary.BigEndian.PutUint16(ansHdr[4:6], 0x0001) // CLASS IN
	binary.BigEndian.PutUint32(ansHdr[6:10], 0)     // TTL 0 (Do not cache)
	resp = append(resp, ansHdr...)

	// RDATA: Character-string (1 byte length + data)
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(1+len(txtPayload)))
	resp = append(resp, rdLen...)
	resp = append(resp, byte(len(txtPayload)))
	resp = append(resp, txtPayload...)

	return resp, nil
}

// ParseDNSTXTResponse extracts character-string TXT payload from an RFC 1035 DNS response.
func ParseDNSTXTResponse(respPacket []byte) (txtPayload []byte, err error) {
	if len(respPacket) < 12 {
		return nil, ErrDNSInvalidQuery
	}

	ancount := binary.BigEndian.Uint16(respPacket[6:8])
	if ancount == 0 {
		return nil, errors.New("dns response: no answer records")
	}

	// Skip Question section
	offset := 12
	for offset < len(respPacket) {
		length := int(respPacket[offset])
		offset++
		if length == 0 {
			break
		}
		offset += length
	}
	offset += 4 // Skip QTYPE + QCLASS
	if offset > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}

	// Parse Answer
	if offset+10 > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}

	// Skip Name pointer (2B), TYPE (2B), CLASS (2B), TTL (4B)
	offset += 10
	if offset+2 > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}
	rdLength := int(binary.BigEndian.Uint16(respPacket[offset : offset+2]))
	offset += 2

	if offset+rdLength > len(respPacket) || rdLength < 1 {
		return nil, ErrDNSInvalidQuery
	}

	txtLen := int(respPacket[offset])
	offset++
	if offset+txtLen > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}

	return append([]byte(nil), respPacket[offset:offset+txtLen]...), nil
}

// RealSocketDNSUpstreamSender transmits frames by fragmenting into DNS QNAME queries over a real UDP socket.
type RealSocketDNSUpstreamSender struct {
	conn         *net.UDPConn
	resolverAddr *net.UDPAddr
	domainSuffix string
	clientID     string
	offset       uint32
	mu           sync.Mutex
}

func NewRealSocketDNSUpstreamSender(conn *net.UDPConn, resolverAddr *net.UDPAddr, domainSuffix, clientID string) *RealSocketDNSUpstreamSender {
	return &RealSocketDNSUpstreamSender{
		conn:         conn,
		resolverAddr: resolverAddr,
		domainSuffix: domainSuffix,
		clientID:     clientID,
	}
}

func (s *RealSocketDNSUpstreamSender) SendUpstream(ctx context.Context, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.offset++
	curOffset := s.offset

	// Split frame into labels fitting RFC 1035 length <= 63 (35 raw bytes -> 56 base32 chars)
	const chunkSize = 35
	totalParts := uint8((len(frame) + chunkSize - 1) / chunkSize)
	if totalParts == 0 {
		totalParts = 1
	}

	for i := uint8(0); i < totalParts; i++ {
		start := int(i) * chunkSize
		end := start + chunkSize
		if end > len(frame) {
			end = len(frame)
		}
		chunk := frame[start:end]

		qname := EncodeDNSQName(s.domainSuffix, s.clientID, curOffset, i, totalParts, chunk)
		queryPkt := BuildDNSQuery(qname, 0x0010 /* TXT */, uint16(curOffset+uint32(i)))

		if _, err := s.conn.WriteToUDP(queryPkt, s.resolverAddr); err != nil {
			return fmt.Errorf("dns sendto %s: %w", s.resolverAddr, err)
		}
	}

	return nil
}

func (s *RealSocketDNSUpstreamSender) Close() error {
	return s.conn.Close()
}

// RealSocketDirectUDPReceiver receives return frames directly from a real UDP socket.
type RealSocketDirectUDPReceiver struct {
	conn *net.UDPConn
}

func NewRealSocketDirectUDPReceiver(conn *net.UDPConn) *RealSocketDirectUDPReceiver {
	return &RealSocketDirectUDPReceiver{conn: conn}
}

func (r *RealSocketDirectUDPReceiver) RecvDownstream(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 2048)
	n, _, err := r.conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func (r *RealSocketDirectUDPReceiver) Close() error {
	return r.conn.Close()
}
