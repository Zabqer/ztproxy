package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	// "github.com/elazarl/goproxy"
	// "github.com/elazarl/goproxy/ext/auth"
	"github.com/zabqer/gologger"
	"golang.org/x/term"
)

var logger *gologger.Logger

type Config struct {
	ProxyPort uint              `json:"proxy_port"`
	Users     map[string]string `json:"users"`
	CertFile  string            `json:"cert_file"`
	KeyFile   string            `json:"key_file"`
}

var config *Config

func interactiveAsk(text string) string {
	var ans string
	fmt.Print("> ")
	fmt.Print(text)
	fmt.Print(": ")
	fmt.Scanln(&ans)
	return ans
}

func checkAnswer(text string, def bool) bool {
	if text == "" {
		return def
	}
	text = strings.ToLower(text)
	return text == "y"
}

func interactiveCreateConfig() (*Config, error) {
	logger.Debug("Running interactive config creation")
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, errors.New("running non-interactive")
	}

	ans := interactiveAsk("Proxy port (default: 8888)")
	var port uint
	if ans != "" {
		if p, err := strconv.Atoi(ans); err != nil {
			port = uint(p)
		}
	}
	if port == 0 {
		port = 8888
	}
	ans = interactiveAsk("Fullchain cert (default: ./fullchain.pem)")
	certfile := "./fullchain.pem"
	if ans != "" {
		certfile = ans
	}
	ans = interactiveAsk("Private key (default: ./privkey.pem)")
	keyfile := "./privkey.pem"
	if ans != "" {
		keyfile = ans
	}
	users := make(map[string]string)
	for {
		ans := interactiveAsk("Do you want to add user? [y/n] (default: n)")
		if !checkAnswer(ans, false) {
			break
		}
		username := interactiveAsk("Enter username")
		if username == "" {
			break
		}
		password := interactiveAsk("Enter password")
		if password == "" {
			break
		}
		users[username] = password
		fmt.Println("User", username, "added")

	}

	return &Config{
		ProxyPort: port,
		CertFile:  certfile,
		KeyFile:   keyfile,
		Users:     users,
	}, nil
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)

	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()

	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func verifyLoginPassword(u, p string) bool {
	if pwd, ok := config.Users[strings.ToLower(u)]; ok {
		if p == pwd {
			return true
		}
	}
	logger.Debug("Failed verify login password for user", u)
	return false
}

func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

func main() {
	logger = gologger.NewLogger()

	data, err := os.ReadFile("config.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Error("Config file doen't exists")
			config, err = interactiveCreateConfig()
			if err != nil {
				logger.Error("Failed to run interactive config creation:", err)
				return
			}
			data, err := json.Marshal(config)
			if err != nil {
				logger.Error("Failed to marshal config:", err)
				return
			}
			os.WriteFile("config.json", data, 0644)
		} else {
			logger.Error("Cannot read config file:", err)
			return
		}
	} else {
		err = json.Unmarshal(data, &config)
		if err != nil {
			logger.Error("Failed to unmarshal config file:", err)
			return
		}
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", config.ProxyPort),

		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("Recived request", r.Method, "from", r.RemoteAddr, "to", r.Host)
			u, p, ok := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
			if !ok || !verifyLoginPassword(u, p) {
				w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
				http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
				return
			}
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),

		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	logger.Error(server.ListenAndServeTLS(config.CertFile, config.KeyFile))
}
