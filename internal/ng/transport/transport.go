package transport

import (
	"context"
	"io"
	"net"

	"github.com/xtaci/smux"
)

// Session represents an authenticated multiplexed transport session.
type Session interface {
	io.Closer
	OpenStream() (net.Conn, error)
	AcceptStream() (net.Conn, error)
	IsClosed() bool
	RemoteAddr() net.Addr
}

// smuxSessionWrapper wraps an *smux.Session into Session.
type smuxSessionWrapper struct {
	sess       *smux.Session
	underlying io.Closer
	remote     net.Addr
}

func (s *smuxSessionWrapper) OpenStream() (net.Conn, error) {
	strm, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Stream: strm, remote: s.remote}, nil
}

func (s *smuxSessionWrapper) AcceptStream() (net.Conn, error) {
	strm, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Stream: strm, remote: s.remote}, nil
}

func (s *smuxSessionWrapper) Close() error {
	var err1, err2 error
	if s.sess != nil {
		err1 = s.sess.Close()
	}
	if s.underlying != nil {
		err2 = s.underlying.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *smuxSessionWrapper) IsClosed() bool {
	return s.sess.IsClosed()
}

func (s *smuxSessionWrapper) RemoteAddr() net.Addr {
	return s.remote
}

// streamConn adapts an smux.Stream to a full net.Conn.
type streamConn struct {
	*smux.Stream
	remote net.Addr
}

func (c *streamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *streamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// Dialer defines the interface to establish an outgoing transport connection.
type Dialer interface {
	Dial(ctx context.Context, addr string) (Session, error)
}

// Listener defines the interface to accept inbound transport connections.
type Listener interface {
	io.Closer
	Accept(ctx context.Context) (Session, error)
	Addr() net.Addr
}
