package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type PathRule struct {
	Scheme   string
	Host     string
	Path     string
	FilePath string
}

// 新增代理规则结构体
type ProxyRule struct {
	Type   string // "host" 或 "url"
	Match  string // 匹配内容
	Target string // 目标地址
}

type Config struct {
	Hosts       map[string]struct{}
	PathRules   []PathRule
	ProxyRules  []ProxyRule // 新增代理规则
	caCert      *x509.Certificate
	caPrivKey   *ecdsa.PrivateKey
	certCache   sync.Map
}

var config = &Config{
	Hosts:      make(map[string]struct{}),
	PathRules:  make([]PathRule, 0),
	ProxyRules: make([]ProxyRule, 0), // 初始化代理规则
}

func generateRootCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2023),
		Subject:               pkix.Name{CommonName: "My Custom CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(certBytes)
	return caCert, caPrivKey, err
}

func generateDomainCert(domain string, caCert *x509.Certificate, caPrivKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 30),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader, template, caCert, &privKey.PublicKey, caPrivKey)
	return certBytes, privKey, err
}

func initConfig() error {
	if err := parseHosts("/dksoft/conf/hosts"); err != nil {
		return err
	}

	if err := parseUrlConfig("/dksoft/conf/url.cfg"); err != nil {
		return err
	}

	// 新增代理配置解析
	if err := parseProxyConfig("/dksoft/conf/proxy.cfg"); err != nil {
		return err
	}

	caCert, caPrivKey, err := generateRootCA()
	if err != nil {
		return fmt.Errorf("生成CA证书失败: %v", err)
	}
	config.caCert = caCert
	config.caPrivKey = caPrivKey

	sort.Slice(config.PathRules, func(i, j int) bool {
		if config.PathRules[i].Host != "" && config.PathRules[j].Host == "" {
			return true
		}
		return len(config.PathRules[i].Path) > len(config.PathRules[j].Path)
	})

	return nil
}

// 新增代理配置文件解析
func parseProxyConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在不报错
		}
		return fmt.Errorf("无法打开proxy.cfg文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}

		ruleType := strings.TrimSuffix(parts[0], ":")
		match := parts[1]
		target := parts[2]

		if strings.ToLower(ruleType) == "host" || strings.ToLower(ruleType) == "url" {
			config.ProxyRules = append(config.ProxyRules, ProxyRule{
				Type:   strings.ToLower(ruleType),
				Match:  match,
				Target: target,
			})
		}
	}
	return nil
}

func parseHosts(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法打开hosts文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		domain := fields[1]
		config.Hosts[domain] = struct{}{}
	}
	return nil
}

func parseUrlConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法打开url.cfg文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			break
		}
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			parts = strings.Fields(line)
			if len(parts) != 2 {
				continue
			}
		}

		rawPattern := strings.TrimSpace(parts[0])
		filePath := strings.TrimSpace(parts[1])

		var rule PathRule
		if u, err := url.Parse(rawPattern); err == nil {
			rule.Scheme = u.Scheme
			rule.Host = u.Hostname()
			rule.Path = u.Path
			if rule.Path == "" {
				rule.Path = "/"
			}
		} else {
			rule.Path = rawPattern
		}

		if strings.Contains(filePath, "dkay-scripts") {
			rule.FilePath = filepath.Join("/dksoft/html", filePath)
		} else {
			rule.FilePath = filepath.Clean(filePath)
		}

		config.PathRules = append(config.PathRules, rule)
	}
	return nil
}

func getCert(domain string) (*tls.Certificate, error) {
	if cert, ok := config.certCache.Load(domain); ok {
		return cert.(*tls.Certificate), nil
	}

	certBytes, privKey, err := generateDomainCert(domain, config.caCert, config.caPrivKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privKey,
	}
	config.certCache.Store(domain, tlsCert)
	return tlsCert, nil
}

// 新增反向代理处理
func handleProxy(target string, w http.ResponseWriter, r *http.Request) {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = target
			req.Host = target // 保持Host头一致
		},
		ModifyResponse: func(resp *http.Response) error {
			log.Printf("[%s]%s --- 代理到 %s (状态码: %d)", 
				r.Host, r.URL.Path, target, resp.StatusCode)
			return nil
		},
	}
	proxy.ServeHTTP(w, r)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := config.Hosts[r.Host]; !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "503 Service Unavailable")
		return
	}

	// 优先处理代理规则
	var proxyTarget string
	// 先检查host类型规则
	for _, rule := range config.ProxyRules {
		if rule.Type == "host" && rule.Match == r.Host {
			proxyTarget = rule.Target
			break
		}
	}
	// 如果没有host匹配，检查url类型规则
	if proxyTarget == "" {
		for _, rule := range config.ProxyRules {
			if rule.Type == "url" && strings.Contains(r.URL.Path, rule.Match) {
				proxyTarget = rule.Target
				break
			}
		}
	}

	if proxyTarget != "" {
		handleProxy(proxyTarget, w, r)
		return
	}

	// 原始文件服务逻辑
	var targetFile string
	for _, rule := range config.PathRules {
		if rule.Host != "" && rule.Host != r.Host {
			continue
		}

		if r.URL.Path == rule.Path {
			targetFile = rule.FilePath
			break
		}
	}

	if targetFile == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	content, err := os.ReadFile(targetFile)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", getContentType(targetFile))
	w.WriteHeader(http.StatusOK)
	w.Write(content)
	log.Printf("[%s]%s --- 文件响应", r.Host, r.URL.Path)
}

func getContentType(filename string) string {
	ext := filepath.Ext(filename)
	switch ext {
	case ".html": return "text/html"
	case ".txt":  return "text/plain"
	case ".json": return "application/json"
	case ".exe":  return "application/octet-stream"
	default:      return "text/plain"
	}
}

func startServer(port string, tlsConf *tls.Config) {
	server := &http.Server{
		Addr:      ":" + port,
		Handler:   http.HandlerFunc(handleRequest),
		TLSConfig: tlsConf,
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", port, err)
	}

	if tlsConf != nil {
		ln = tls.NewListener(ln, tlsConf)
	}

	log.Printf("服务启动，监听 %s 端口", port)
	if err := server.Serve(ln); err != nil {
		log.Fatal("服务器启动失败: ", err)
	}
}

func main() {
	if err := initConfig(); err != nil {
		log.Fatal("配置初始化失败: ", err)
	}

	log.Println("加载的代理规则:")
	for _, rule := range config.ProxyRules {
		log.Printf("%s规则 [%s] => %s", rule.Type, rule.Match, rule.Target)
	}

	log.Println("加载的URL映射规则:")
	for _, rule := range config.PathRules {
		log.Printf("%s://%s%s => %s", rule.Scheme, rule.Host, rule.Path, rule.FilePath)
	}

	tlsConf := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return getCert(info.ServerName)
		},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	go startServer("80", nil)
	go startServer("443", tlsConf)

	select {}
}