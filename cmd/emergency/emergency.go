package emergency

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
	keyFile       string
	clientID      string
	messageStr    string
	timeoutSec    int
	scanResolvers string
	scanCacheFile string
	bootstrapPort int
	bootstrapMode string
)

func init() {
	Cmd.AddCommand(serverCmd)
	Cmd.AddCommand(sendCmd)
	Cmd.AddCommand(scanCmd)

	serverCmd.Flags().StringVar(&listenAddr, "addr", ":53", "Authoritative DNS listening UDP and TCP address")
	serverCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Delegated child domain suffix")
	serverCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing 32-byte shared key (prefer over --key)")
	serverCmd.Flags().StringVar(&keyStr, "key", "", "Base64 or hex 32-byte shared key (prefer --key-file or $PAQET_EMERGENCY_KEY to prevent process argument exposure)")
	serverCmd.Flags().IntVar(&bootstrapPort, "bootstrap-port", 18089, "Candidate recovery port advertised in bootstrap responses")
	serverCmd.Flags().StringVar(&bootstrapMode, "bootstrap-mode", "aead-stream", "Candidate recovery transport mode advertised in bootstrap responses")

	sendCmd.Flags().StringVar(&resolverAddr, "resolver", "8.8.8.8:53", "Recursive DNS resolver address (e.g. 8.8.8.8:53)")
	sendCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir", "Delegated child domain suffix")
	sendCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing 32-byte shared key (prefer over --key)")
	sendCmd.Flags().StringVar(&keyStr, "key", "", "Base64 or hex 32-byte shared key (prefer --key-file or $PAQET_EMERGENCY_KEY to prevent process argument exposure)")
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
		psk, err := parseKey(keyStr, keyFile)
		if err != nil {
			log.Fatalf("failed to load emergency key: %v", err)
		}

		srv, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
			ListenAddr:   listenAddr,
			DomainSuffix: domainSuffix,
			PSK:          psk,
			Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
				// Privacy and Security: Log only metadata, never plaintext payload or key material
				log.Printf("[EMERGENCY-SERVER] Authenticated message ID=%s Type=%s PayloadBytes=%d ClientID=%s Status=PROCESSED",
					msg.ID, msg.Type, len(msg.Payload), clientID)

				if msg.Type == "bootstrap_request" {
					port := bootstrapPort
					if port <= 0 {
						port = 18089
					}
					mode := bootstrapMode
					if mode == "" {
						mode = "aead-stream"
					}
					bootstrapResp := transport.BootstrapEndpointData{
						ServerIP:      "77.37.65.2",
						TransportPort: port,
						TransportMode: mode,
						ServerPubKey:  fmt.Sprintf("SHA256:%x", sha256.Sum256(psk)),
						ValidUntil:    time.Now().Add(2 * time.Hour).Unix(),
					}
					payload, err := json.Marshal(bootstrapResp)
					if err == nil {
						return &transport.EmergencyResponse{
							ID:        msg.ID,
							Status:    "OK",
							Reply:     payload,
							Timestamp: time.Now().Unix(),
						}, nil
					}
				}

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

		log.Printf("[EMERGENCY-SERVER] Listening on %s (UDP+TCP) for domain *.%s", srv.Addr(), domainSuffix)

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
		psk, err := parseKey(keyStr, keyFile)
		if err != nil {
			log.Fatalf("failed to load emergency key: %v", err)
		}

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

		msgID := transport.GenerateRandomMessageID()
		msg := &transport.EmergencyMessage{
			ID:        msgID,
			Type:      "alert",
			Payload:   []byte(messageStr),
			Timestamp: time.Now().Unix(),
		}

		fmt.Printf("[CLIENT] Sending emergency message ID=%s (%d bytes) to %s via *.%s...\n",
			msgID, len(msg.Payload), resolverAddr, domainSuffix)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+2)*time.Second)
		defer cancel()

		resp, rtt, err := client.Exchange(ctx, msg)
		if err != nil {
			log.Fatalf("[CLIENT] Exchange failed: %v", err)
		}

		fmt.Printf("[CLIENT] SUCCESS! RTT: %v\n", rtt)
		fmt.Printf(" - Response ID: %s\n", resp.ID)
		fmt.Printf(" - Status:      %s\n", resp.Status)
		fmt.Printf(" - Reply Bytes: %d\n", len(resp.Reply))
		if len(resp.Reply) <= 256 {
			fmt.Printf(" - Reply Echo:  %s\n", string(resp.Reply))
		} else {
			fmt.Printf(" - Reply Echo:  %s... (truncated preview)\n", string(resp.Reply[:64]))
		}
	},
}

func parseKey(kStr, kFile string) ([]byte, error) {
	var rawStr string

	if kFile != "" {
		data, err := os.ReadFile(kFile)
		if err != nil {
			return nil, fmt.Errorf("read key file %s: %w", kFile, err)
		}
		rawStr = strings.TrimSpace(string(data))
	} else if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		credPath := filepath.Join(credDir, "emergency_key")
		if data, err := os.ReadFile(credPath); err == nil {
			rawStr = strings.TrimSpace(string(data))
		}
	}

	if rawStr == "" {
		if envKey := os.Getenv("PAQET_EMERGENCY_KEY"); envKey != "" {
			rawStr = strings.TrimSpace(envKey)
		}
	}

	if rawStr == "" && kStr != "" {
		rawStr = strings.TrimSpace(kStr)
	}

	if rawStr == "" {
		return nil, errors.New("no emergency key provided. An explicit 32-byte key must be supplied via --key-file, $PAQET_EMERGENCY_KEY, or --key")
	}

	// 1. Try base64
	if b, err := base64.StdEncoding.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}

	// 2. Try hex
	if b, err := hex.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}

	// 3. Try raw bytes
	if len(rawStr) == 32 {
		return []byte(rawStr), nil
	}

	return nil, fmt.Errorf("invalid key length (got %d chars). Key must decode to exactly 32 bytes (base64, hex, or raw). Zero-padding and truncation are rejected for security", len(rawStr))
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

		fmt.Printf("%-18s %-8s %-18s %-6s %-10s %-8s %-8s %-10s\n",
			"RESOLVER", "STATUS", "PROFILE", "SCORE", "LATENCY", "EDNS0", "NXDOMAIN", "CAPABILITY")
		fmt.Println(strings.Repeat("-", 97))

		for _, r := range results {
			nxStatus := "HIJACKED"
			if r.NXDOMAINPreserved {
				nxStatus = "CLEAN"
			}
			ednsStr := fmt.Sprintf("%dB", r.EDNS0MaxPayload)
			if !r.EDNS0Support {
				ednsStr = "NONE"
			}
			capabilityStr := "FAIL"
			if r.SupportsLongLabels && r.SupportsTXT {
				capabilityStr = "PASS"
			}

			fmt.Printf("%-18s %-8s %-18s %d/6    %-10s %-8s %-8s %-10s\n",
				r.Host, r.Status, r.Profile, r.Score,
				fmt.Sprintf("%.1fms", float64(r.Latency.Microseconds())/1000.0),
				ednsStr, nxStatus, capabilityStr)
		}

		fmt.Println("\nNote: 'CAPABILITY PASS' verifies DNS protocol, long label, and TXT capability.")
		fmt.Println("      It does NOT guarantee end-to-end transport without an authenticated payload exchange.")

		if len(results) > 0 && results[0].Score >= 4 && results[0].NXDOMAINPreserved {
			fmt.Printf("\n[RECOMMENDATION] Optimal candidate resolver: %s:53 (Score %d/6, Latency %v)\n",
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
