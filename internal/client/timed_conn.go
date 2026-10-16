package client

import (
	"net"
	"time"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/ng/transport"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"paqet/internal/tnet/stream"
)

type timedConn struct {
	cfg            *conf.Conf
	conn           tnet.Conn
	expire         time.Time
	index          int
	recoveryEngine *transport.RecoveryStateMachine
}

func newTimedConn(cfg *conf.Conf, index int, re *transport.RecoveryStateMachine) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, index: index, recoveryEngine: re}
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
	re := tc.recoveryEngine
	if re != nil && re.CurrentState() == transport.StateRecoveryReady {
		snapshot := re.ActiveSnapshot()
		if snapshot != nil {
			now := time.Now()
			if snapshot.IsExpired(now) {
				re.ReportCandidateFailure(transport.ErrStaleBootstrapData)
			} else {
				flog.Infof("[RECOVERY-FAILOVER] Routing connection to validated recovery candidate %s (%s)",
					snapshot.Addr(), snapshot.TransportMode)
				switch snapshot.TransportMode {
				case transport.ModeAEADStream:
					conn, err := stream.Dial(snapshot.Addr(), tc.cfg.Transport.Obfs)
					if err == nil {
						return conn, nil
					}
					re.ReportCandidateFailure(err)
					flog.Errorf("[RECOVERY-FAILOVER] Candidate %s dial failed: %v", snapshot.Addr(), err)
				case transport.ModeTLSStream:
					conn, err := stream.DialTLS(snapshot.Addr(), tc.cfg.Transport.Obfs, tc.cfg.Transport.TLS)
					if err == nil {
						return conn, nil
					}
					re.ReportCandidateFailure(err)
					flog.Errorf("[RECOVERY-FAILOVER] Candidate %s dial failed: %v", snapshot.Addr(), err)
				case transport.ModeRawKCP:
					netCfg := tc.cfg.Network
					netCfg.SNI = tc.cfg.Transport.SNI
					udpAddr, err := net.ResolveUDPAddr("udp", snapshot.Addr())
					if err != nil {
						re.ReportCandidateFailure(err)
						flog.Errorf("[RECOVERY-FAILOVER] ResolveUDPAddr %s failed: %v", snapshot.Addr(), err)
						break
					}
					conn, err := kcp.Dial(udpAddr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, netCfg)
					if err == nil {
						_ = tc.sendTCPF(conn)
						return conn, nil
					}
					re.ReportCandidateFailure(err)
					flog.Errorf("[RECOVERY-FAILOVER] Candidate %s dial failed: %v", snapshot.Addr(), err)
				}
			}
		}
	}

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
	case "tls", "tls-stream":
		conn, err := stream.DialTLS(target, tc.cfg.Transport.Obfs, tc.cfg.Transport.TLS)
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
			netCfg := tc.cfg.Network
			netCfg.SNI = tc.cfg.Transport.SNI
			kcpConn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, netCfg)
			if err == nil {
				_ = tc.sendTCPF(kcpConn)
				return kcpConn, nil
			}
		}
		return nil, err
	default:
		netCfg := tc.cfg.Network
		netCfg.SNI = tc.cfg.Transport.SNI
		conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, netCfg)
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
