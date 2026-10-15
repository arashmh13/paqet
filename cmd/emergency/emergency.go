package emergency

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"paqet/internal/ng/transport"
)

var (
	listenAddr   string
	resolverAddr string
	domainSuffix string
	keyStr       string
	clientID     string
	messageStr   string
	timeoutSec   int
)

func init() {
	Cmd.AddCommand(serverCmd)
	Cmd.AddCommand(sendCmd)

	serverCmd.Flags().StringVar(&listenAddr, "addr", ":53", "Authoritative DNS listening UDP address")
	serverCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Delegated child domain suffix")
	serverCmd.Flags().StringVar(&keyStr, "key", "yP9v/8x+n3Lp+ZqW4s1RjT5oK2a9XbE8vM7JdH4=", "Base64 or raw 32-byte shared key")

	sendCmd.Flags().StringVar(&resolverAddr, "resolver", "8.8.8.8:53", "Recursive DNS resolver address (e.g. 8.8.8.8:53)")
	sendCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Delegated child domain suffix")
	sendCmd.Flags().StringVar(&keyStr, "key", "yP9v/8x+n3Lp+ZqW4s1RjT5oK2a9XbE8vM7JdH4=", "Base64 or raw 32-byte shared key")
	sendCmd.Flags().StringVar(&clientID, "client-id", "c01", "Client ID string (max 4 chars)")
	sendCmd.Flags().StringVarP(&messageStr, "message", "m", "EMERGENCY_PING", "Application payload to transmit")
	sendCmd.Flags().IntVar(&timeoutSec, "timeout", 5, "Timeout in seconds for response")
}

// Cmd is the root emergency command.
var Cmd = &cobra.Command{
	Use:   "emergency",
	Short: "Authenticated emergency messaging and signaling over recursive DNS",
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Runs the authoritative emergency DNS daemon",
	Run: func(cmd *cobra.Command, args []string) {
		psk := parseKey(keyStr)

		srv, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
			ListenAddr:   listenAddr,
			DomainSuffix: domainSuffix,
			PSK:          psk,
			Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
				log.Printf("[EMERGENCY-SERVER] Received authenticated msg ID=%s Type=%s Payload=%q",
					msg.ID, msg.Type, string(msg.Payload))
				return &transport.EmergencyResponse{
					ID:        msg.ID,
					Status:    "OK",
					Reply:     append([]byte("ACK_ECHO:"), msg.Payload...),
					Timestamp: time.Now().Unix(),
				}, nil
			},
		})
		if err != nil {
			log.Fatalf("failed to start emergency dns server: %v", err)
		}
		defer srv.Stop()

		log.Printf("[EMERGENCY-SERVER] Listening on %s for domain *.%s", srv.Addr(), domainSuffix)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("[EMERGENCY-SERVER] Shutting down...")
	},
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Transmits an authenticated emergency message over recursive DNS and waits for reply",
	Run: func(cmd *cobra.Command, args []string) {
		psk := parseKey(keyStr)

		client, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
			ResolverAddr: resolverAddr,
			DomainSuffix: domainSuffix,
			ClientID:     clientID,
			PSK:          psk,
			Timeout:      time.Duration(timeoutSec) * time.Second,
			MaxRetries:   2,
		})
		if err != nil {
			log.Fatalf("failed to initialize emergency client: %v", err)
		}

		msgID := fmt.Sprintf("msg-%d", time.Now().UnixNano()%1000000)
		msg := &transport.EmergencyMessage{
			ID:        msgID,
			Type:      "alert",
			Payload:   []byte(messageStr),
			Timestamp: time.Now().Unix(),
		}

		fmt.Printf("[CLIENT] Sending emergency message ID=%s to %s via *.%s...\n", msgID, resolverAddr, domainSuffix)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+2)*time.Second)
		defer cancel()

		resp, rtt, err := client.Exchange(ctx, msg)
		if err != nil {
			log.Fatalf("[CLIENT] Exchange failed: %v", err)
		}

		fmt.Printf("[CLIENT] SUCCESS! RTT: %v\n", rtt)
		fmt.Printf(" - Response ID: %s\n", resp.ID)
		fmt.Printf(" - Status:      %s\n", resp.Status)
		fmt.Printf(" - Reply:       %s\n", string(resp.Reply))
	},
}

func parseKey(k string) []byte {
	if b, err := base64.StdEncoding.DecodeString(k); err == nil && len(b) == 32 {
		return b
	}
	raw := []byte(k)
	if len(raw) >= 32 {
		return raw[:32]
	}
	padded := make([]byte, 32)
	copy(padded, raw)
	return padded
}
