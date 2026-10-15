package stream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/xtaci/smux"

	"paqet/internal/conf"
	"paqet/internal/ng/transport"
	"paqet/internal/tnet"
)

// DialTLS establishes an authentic TLS 1.3 outer connection and wraps it into tnet.Conn.
func DialTLS(addr string, obfsCfg *conf.Obfs, tlsCfg *conf.TLS) (tnet.Conn, error) {
	netDialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := netDialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls stream: dial %s failed: %w", addr, err)
	}
	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	serverName := ""
	insecureSkipVerify := true
	alpn := []string{"h2", "http/1.1"}
	var rootCAs *x509.CertPool

	if tlsCfg != nil {
		serverName = tlsCfg.ServerName
		insecureSkipVerify = tlsCfg.InsecureSkipVerify
		if len(tlsCfg.ALPN) > 0 {
			alpn = tlsCfg.ALPN
		}
		if tlsCfg.CAFile != "" {
			caData, err := os.ReadFile(tlsCfg.CAFile)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("tls stream: read ca file %s: %w", tlsCfg.CAFile, err)
			}
			rootCAs = x509.NewCertPool()
			if !rootCAs.AppendCertsFromPEM(caData) {
				rawConn.Close()
				return nil, fmt.Errorf("tls stream: failed to parse ca pem in %s", tlsCfg.CAFile)
			}
		}
	}
	if serverName == "" {
		host, _, _ := net.SplitHostPort(addr)
		serverName = host
	}

	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         alpn,
	}

	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls stream: client handshake failed: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024

	sess, err := smux.Client(tlsConn, smuxCfg)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls stream: smux client init: %w", err)
	}

	return &Conn{
		underlying: tlsConn,
		session:    sess,
		rawConn:    rawConn,
	}, nil
}

// TLSListener wraps net.Listener to accept genuine TLS connections into tnet.Conn.
type TLSListener struct {
	listener  net.Listener
	tlsConfig *tls.Config
}

// ListenTLS starts a genuine TLS server listener.
func ListenTLS(addr string, obfsCfg *conf.Obfs, tlsCfg *conf.TLS) (tnet.Listener, error) {
	var cert tls.Certificate
	var err error

	if tlsCfg != nil && tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls stream: failed to load keypair: %w", err)
		}
	} else {
		certName := "paqet.local"
		if tlsCfg != nil && tlsCfg.ServerName != "" {
			certName = tlsCfg.ServerName
		}
		cert, err = transport.GenerateSelfSignedCertificate(certName)
		if err != nil {
			return nil, fmt.Errorf("tls stream: generate cert failed: %w", err)
		}
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls stream: failed to listen on %s: %w", addr, err)
	}

	alpn := []string{"h2", "http/1.1"}
	if tlsCfg != nil && len(tlsCfg.ALPN) > 0 {
		alpn = tlsCfg.ALPN
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
	}

	return &TLSListener{
		listener:  l,
		tlsConfig: config,
	}, nil
}

func (l *TLSListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *TLSListener) Close() error {
	return l.listener.Close()
}

func (l *TLSListener) SetClientTCPF(addr net.Addr, f []conf.TCPF)       {}
func (l *TLSListener) DeleteClientTCPF(addr net.Addr)                   {}
func (l *TLSListener) UpdateConfig(network conf.Network, kcp *conf.KCP) {}

func (l *TLSListener) Accept() (tnet.Conn, error) {
	for {
		rawConn, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}
		if tcp, ok := rawConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}

		rawConn.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConn := tls.Server(rawConn, l.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			continue
		}
		rawConn.SetDeadline(time.Time{})

		smuxCfg := smux.DefaultConfig()
		smuxCfg.Version = 2
		smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
		smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024

		sess, err := smux.Server(tlsConn, smuxCfg)
		if err != nil {
			tlsConn.Close()
			continue
		}

		return &Conn{
			underlying: tlsConn,
			session:    sess,
			rawConn:    rawConn,
		}, nil
	}
}
