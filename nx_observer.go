package openvpn

import (
	"net/netip"
	"strings"
	"time"
)

// NX fork: what a TLS server's sessions do, for the node's path telemetry.
// Like source_user.go this is NX's own file; the hooks into upstream's code
// are one line each (grep for "NX").

// PeerObserver is told how each TLS session of a server goes, by the client's
// address and the transport it came over ("udp" or "tcp"). Calls come from the
// server's own goroutines and must return quickly.
type PeerObserver interface {
	// PeerStarted: a session opened for a client.
	PeerStarted(peer netip.AddrPort, network string)
	// PeerAuthed: the session got its first push reply — the client is in.
	PeerAuthed(peer netip.AddrPort, network string)
	// PeerEnded: the session is over; connected says whether it got in, err
	// is how it ended (ErrAuthenticationFailed for a refused login).
	PeerEnded(peer netip.AddrPort, network string, connected bool, lasted time.Duration, err error)
}

type observerBox struct{ PeerObserver }

// SetObserver sets the server's PeerObserver; nil removes it.
func (s *Server) SetObserver(observer PeerObserver) {
	if observer == nil {
		s.nxObserver.Store(nil)
		return
	}
	s.nxObserver.Store(&observerBox{observer})
}

func (s *Server) observer() PeerObserver {
	if box := s.nxObserver.Load(); box != nil {
		return box.PeerObserver
	}
	return nil
}

// nxPeer is the session's client address and transport. peerAddress may carry
// a "#session=N" suffix for a second session from one address.
func (s *tlsServerSession) nxPeer() (netip.AddrPort, string) {
	address, _, _ := strings.Cut(s.peerAddress, "#")
	peer, _ := netip.ParseAddrPort(address)
	network := "tcp"
	if _, isUDP := s.packetConnection.(*udpPeerPacketConnection); isUDP {
		network = "udp"
	}
	return peer, network
}

func (s *tlsServerSession) nxObserveStarted() {
	s.nxStarted = time.Now()
	if o := s.server.parent.observer(); o != nil {
		peer, network := s.nxPeer()
		o.PeerStarted(peer, network)
	}
}

func (s *tlsServerSession) nxObserveAuthed() {
	if o := s.server.parent.observer(); o != nil {
		peer, network := s.nxPeer()
		o.PeerAuthed(peer, network)
	}
}

func (s *tlsServerSession) nxObserveEnded(err error) {
	if o := s.server.parent.observer(); o != nil && !s.nxStarted.IsZero() {
		peer, network := s.nxPeer()
		o.PeerEnded(peer, network, s.connected, time.Since(s.nxStarted), err)
	}
}
