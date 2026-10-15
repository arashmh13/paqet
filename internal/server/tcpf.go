package server

import (
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

func (s *Server) handleTCPF(strm tnet.Strm, p *protocol.Proto) {
	for _, l := range s.listeners {
		if len(p.TCPF) == 0 {
			l.DeleteClientTCPF(strm.RemoteAddr())
		} else {
			l.SetClientTCPF(strm.RemoteAddr(), p.TCPF)
		}
	}
}
