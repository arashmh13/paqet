package server

import (
	"context"
	"fmt"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"paqet/internal/tnet/stream"
)

type Server struct {
	cfg      *conf.Conf
	listener tnet.Listener
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{cfg: cfg}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	var listener tnet.Listener
	var err error

	switch s.cfg.Transport.Protocol {
	case "stream", "aead-stream", "sni-assisted", "auto":
		listener, err = stream.Listen(s.cfg.Listen.Addr.String(), s.cfg.Transport.Obfs)
		if err != nil {
			return fmt.Errorf("could not start stream listener: %w", err)
		}
		flog.Infof("server listening for stream connections on %s", s.cfg.Listen.Addr.String())
	default:
		listener, err = kcp.Listen(s.cfg.Transport.KCP, s.cfg.Transport.Obfs, s.cfg.Network)
		if err != nil {
			return fmt.Errorf("could not start KCP listener: %w", err)
		}
		flog.Infof("server listening for packets on :%d", s.cfg.Listen.Addr.Port)
	}

	s.listener = listener

	go s.listen(ctx, listener)
	context.AfterFunc(ctx, func() { listener.Close() })

	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		go func() {
			defer conn.Close()
			defer s.listener.DeleteClientTCPF(conn.RemoteAddr())
			s.handleConn(ctx, conn)
		}()
	}
}
