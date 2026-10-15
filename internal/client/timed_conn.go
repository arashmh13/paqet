package client

import (
	"time"

	"paqet/internal/conf"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"paqet/internal/tnet/stream"
)

type timedConn struct {
	cfg    *conf.Conf
	conn   tnet.Conn
	expire time.Time
	index  int
}

func newTimedConn(cfg *conf.Conf, index int) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, index: index}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) getTargetAddr() string {
	if len(tc.cfg.Server.Endpoints) > 0 {
		ep := tc.cfg.Server.Endpoints[tc.index%len(tc.cfg.Server.Endpoints)]
		return ep.String()
	}
	if tc.cfg.Server.Addr != nil {
		return tc.cfg.Server.Addr.String()
	}
	return ""
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	target := tc.getTargetAddr()

	switch tc.cfg.Transport.Protocol {
	case "stream", "aead-stream":
		conn, err := stream.Dial(target, tc.cfg.Transport.Obfs)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case "sni-assisted":
		conn, err := stream.DialSNIAssisted(target, tc.cfg.Transport.Obfs, tc.cfg.Transport.SNI)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case "auto":
		// Auto selector: try sni-assisted, then aead-stream, then kcp
		conn, err := stream.DialSNIAssisted(target, tc.cfg.Transport.Obfs, tc.cfg.Transport.SNI)
		if err == nil {
			return conn, nil
		}
		conn, err = stream.Dial(target, tc.cfg.Transport.Obfs)
		if err == nil {
			return conn, nil
		}
		if tc.cfg.Transport.KCP != nil {
			kcpConn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, tc.cfg.Network)
			if err == nil {
				_ = tc.sendTCPF(kcpConn)
				return kcpConn, nil
			}
		}
		return nil, err
	default:
		conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, tc.cfg.Network)
		if err != nil {
			return nil, err
		}
		err = tc.sendTCPF(conn)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}
