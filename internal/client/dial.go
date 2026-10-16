package client

import (
	"context"
	"time"

	"paqet/internal/flog"
	"paqet/internal/ng/transport"
	"paqet/internal/tnet"
)

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	autoExpire := 300
	tc := c.iter.Next()
	go tc.sendTCPF(tc.conn)

	err := tc.conn.Ping(false)
	needsRecreate := err != nil

	re := c.recoveryEngine
	if re != nil {
		if re.CurrentState() == transport.StateRecoveryReady {
			snapshot := re.ActiveSnapshot()
			if snapshot != nil {
				if tc.conn == nil || tc.conn.RemoteAddr() == nil || tc.conn.RemoteAddr().String() != snapshot.Addr() {
					needsRecreate = true
				}
			}
		} else if re.CurrentState() == transport.StatePrimaryHealthy {
			target := tc.getTargetAddr()
			if target != "" && tc.conn != nil && tc.conn.RemoteAddr() != nil {
				if tc.conn.RemoteAddr().String() != target {
					needsRecreate = true
				}
			}
		}
	}

	if needsRecreate {
		flog.Infof("connection lost or switched to recovery endpoint, recreating connection....")
		if tc.conn != nil {
			tc.conn.Close()
		}
		conn, err := tc.createConn()
		if err != nil {
			if c.recoveryEngine != nil && c.recoveryEngine.CurrentState() != transport.StateRecoveryReady {
				c.recoveryEngine.ReportPrimaryFailure(err)
				_, _ = c.recoveryEngine.Step(context.Background())
			}
			return nil, err
		}
		tc.conn = conn
		tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)
	}
	return tc.conn, nil
}

func (c *Client) newStrm(ctx context.Context) (tnet.Strm, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := c.newConn()
		if err != nil {
			flog.Debugf("failed to open conn, retrying: %v", err)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			flog.Debugf("failed to open stream, retrying: %v", err)
			continue
		}
		return strm, nil
	}
}
