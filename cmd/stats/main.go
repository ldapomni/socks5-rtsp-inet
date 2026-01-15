package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Stats struct {
	Uptime        string `json:"uptime"`
	ActiveTunnels int    `json:"active_tunnels"`

	TCPSent uint64 `json:"tcp_sent"`
	TCPRecv uint64 `json:"tcp_recv"`

	UDPSent     uint64 `json:"udp_sent"`
	UDPRecv     uint64 `json:"udp_recv"`
	UDPSentPkts uint64 `json:"udp_sent_pkts"`
	UDPRecvPkts uint64 `json:"udp_recv_pkts"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "Client stats API address")
	user := flag.String("user", "", "Username for auth")
	pass := flag.String("pass", "", "Password for auth")
	interval := flag.Int("interval", 1000, "Polling interval in milliseconds")
	jsonMode := flag.Bool("json", false, "Output raw JSON")
	addUser := flag.String("add-user", "", "Add user in format 'user:pass[:stat][:admin]'")
	setPass := flag.String("set-pass", "", "Change password for user in format 'user:newpass'")
	flag.Parse()

	if *addUser != "" {
		if err := remoteAddUser(*addr, *user, *pass, *addUser, false); err != nil {
			fmt.Printf("Failed to add user: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("User added/updated successfully")
		return
	}

	if *setPass != "" {
		if err := remoteAddUser(*addr, *user, *pass, *setPass, true); err != nil {
			fmt.Printf("Failed to change password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Password changed successfully")
		return
	}

	if *jsonMode {
		stats, err := fetchStats(*addr, *user, *pass)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Println("RTSP Tunnel Statistics Dashboard")
	fmt.Printf("Connecting to client at http://%s/stats...\n", *addr)

	ticker := time.NewTicker(time.Duration(*interval) * time.Millisecond)
	for range ticker.C {
		stats, err := fetchStats(*addr, *user, *pass)
		if err != nil {
			fmt.Printf("\rError: %v (Is the client running?)          ", err)
			continue
		}

		clearScreen()
		fmt.Println("========================================")
		fmt.Printf("   RTSP TUNNEL MONITORING DASHBOARD     \n")
		fmt.Println("========================================")
		fmt.Printf(" Uptime:         %s\n", stats.Uptime)
		fmt.Printf(" Active Tunnels: %d\n", stats.ActiveTunnels)
		fmt.Println("----------------------------------------")
		fmt.Printf(" TCP Traffic:    ↑ %-10s ↓ %-10s\n", formatBytes(stats.TCPSent), formatBytes(stats.TCPRecv))
		fmt.Printf(" UDP Traffic:    ↑ %-10s ↓ %-10s\n", formatBytes(stats.UDPSent), formatBytes(stats.UDPRecv))
		fmt.Printf(" UDP Packets:    ↑ %-10d ↓ %-10d\n", stats.UDPSentPkts, stats.UDPRecvPkts)
		fmt.Println("========================================")
		fmt.Printf("\n Last Update: %s\n", time.Now().Format("15:04:05"))
	}
}

func remoteAddUser(addr, adminUser, adminPass, input string, isUpdateOnly bool) error {
	parts := strings.Split(input, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid user format, expected 'user:pass[:stat][:admin]'")
	}

	newUser := struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Stats    bool   `json:"stats"`
		Admin    bool   `json:"admin"`
		Update   bool   `json:"update"`
	}{
		Username: parts[0],
		Password: parts[1],
		Update:   isUpdateOnly,
	}

	if !isUpdateOnly {
		for i := 2; i < len(parts); i++ {
			if parts[i] == "stat" {
				newUser.Stats = true
			} else if parts[i] == "admin" {
				newUser.Admin = true
			}
		}
	} else {
		// For password change, we ideally shouldn't need to specify stats/admin
		// The client is currently simple and overwrites, so maybe we should fetch current if it's an update?
		// But stats tool doesn't have a 'get user' API yet.
		// For now, if it's set-pass, we just set the password and default permissions (meaning they might be reset if not specified).
		// Wait, if the client simple overwrites, we should probably fetch current if we want to preserve.
		// Let's assume for now the user is fine with default or will use add-user if they want to keep permissions.
		// Actually, I'll update the client to be smarter.
	}

	url := fmt.Sprintf("http://%s/users", addr)
	body, _ := json.Marshal(newUser)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	if adminUser != "" {
		auth := adminUser + ":" + adminPass
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

func fetchStats(addr, user, pass string) (*Stats, error) {
	url := fmt.Sprintf("http://%s/stats", addr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if user != "" {
		auth := user + ":" + pass
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var stats Stats
	err = json.Unmarshal(body, &stats)
	return &stats, err
}

func formatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%dB", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}
