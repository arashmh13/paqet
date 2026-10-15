package emergency

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"paqet/internal/ng/dns"
	"paqet/internal/ng/transport"
)

var (
	listenAddr    string
	resolverAddr  string
	domainSuffix  string
	keyStr        string
	clientID      string
	messageStr    string
	timeoutSec    int
	scanResolvers string
	scanCacheFile string
)

func init() {
	Cmd.AddCommand(serverCmd)
	Cmd.AddCommand(sendCmd)
	Cmd.AddCommand(scanCmd)

	serverCmd.Flags().StringVar(&listenAddr, "addr", ":53", "Authoritative DNS listening UDP address")
	serverCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Delegated child domain suffix")
	serverCmd.Flags().StringVar(&keyStr, "key", "yP9v/8x+n3Lp+ZqW4s1RjT5oK2a9XbE8vM7JdH4=", "Base64 or raw 32-byte shared key")

	sendCmd.Flags().StringVar(&resolverAddr, "resolver", "8.8.8.8:53", "Recursive DNS resolver address (e.g. 8.8.8.8:53)")
	sendCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Delegated child domain suffix")
	sendCmd.Flags().StringVar(&keyStr, "key", "yP9v/8x+n3Lp+ZqW4s1RjT5oK2a9XbE8vM7JdH4=", "Base64 or raw 32-byte shared key")
	sendCmd.Flags().StringVar(&clientID, "client-id", "c01", "Client ID string (max 4 chars)")
	sendCmd.Flags().StringVarP(&messageStr, "message", "m", "EMERGENCY_PING", "Application payload to transmit")
	sendCmd.Flags().IntVar(&timeoutSec, "timeout", 5, "Timeout in seconds for response")

	scanCmd.Flags().StringVar(&scanResolvers, "resolvers", "", "Comma-separated resolver IPs (default: system + public resolvers)")
	scanCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Target domain suffix")
	scanCmd.Flags().StringVar(&scanCacheFile, "cache", "/tmp/resolver_cache.json", "JSON cache file path")
	scanCmd.Flags().IntVar(&timeoutSec, "timeout", 2, "Timeout per probe in seconds")
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

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Evaluates candidate recursive DNS resolvers for emergency tunnel capability",
	Run: func(cmd *cobra.Command, args []string) {
		var candidates []string
		if scanResolvers != "" {
			for _, r := range strings.Split(scanResolvers, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					candidates = append(candidates, r)
				}
			}
		} else {
			candidates = append(dns.GetSystemResolvers(), dns.DefaultPublicResolvers()...)
		}

		// Deduplicate candidates
		seen := make(map[string]bool)
		var unique []string
		for _, c := range candidates {
			if !seen[c] {
				seen[c] = true
				unique = append(unique, c)
			}
		}

		fmt.Printf("[SCANNER] Evaluating %d candidate resolvers against *.%s (timeout=%ds)...\n\n",
			len(unique), domainSuffix, timeoutSec)

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*4)*time.Second)
		defer cancel()

		results := dns.ScanResolverPool(ctx, unique, 53, domainSuffix, time.Duration(timeoutSec)*time.Second, 4)

		fmt.Printf("%-18s %-8s %-18s %-6s %-10s %-8s %-8s %-8s\n",
			"RESOLVER", "STATUS", "PROFILE", "SCORE", "LATENCY", "EDNS0", "NXDOMAIN", "TUNNEL")
		fmt.Println(strings.Repeat("-", 95))

		for _, r := range results {
			nxStatus := "HIJACKED"
			if r.NXDOMAINPreserved {
				nxStatus = "CLEAN"
			}
			ednsStr := fmt.Sprintf("%dB", r.EDNS0MaxPayload)
			if !r.EDNS0Support {
				ednsStr = "NONE"
			}
			tunnelStr := "FAIL"
			if r.SupportsLongLabels && r.SupportsTXT {
				tunnelStr = "PASS"
			}

			fmt.Printf("%-18s %-8s %-18s %d/6    %-10s %-8s %-8s %-8s\n",
				r.Host, r.Status, r.Profile, r.Score,
				fmt.Sprintf("%.1fms", float64(r.Latency.Microseconds())/1000.0),
				ednsStr, nxStatus, tunnelStr)
		}

		if len(results) > 0 && results[0].Score >= 4 && results[0].NXDOMAINPreserved {
			fmt.Printf("\n[RECOMMENDATION] Optimal unpoisoned resolver: %s:53 (Score %d/6, Latency %v)\n",
				results[0].Host, results[0].Score, results[0].Latency)
		} else {
			fmt.Println("\n[WARNING] No candidate passed all censorship checks with clean NXDOMAIN preservation.")
		}

		if scanCacheFile != "" {
			if err := dns.SaveResolverCache(scanCacheFile, results); err == nil {
				fmt.Printf("[CACHE] Saved results to %s\n", scanCacheFile)
			}
		}
	},
}
