package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	//"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 配置规则结构体
type PathRule struct {
	Scheme   string // 协议（http/https）
	Host     string // 域名
	Path     string // URL路径
	FilePath string // 文件路径
}

type Config struct {
	Hosts     map[string]struct{}
	PathRules []PathRule
	caCert    *x509.Certificate
	caPrivKey *ecdsa.PrivateKey
	certCache sync.Map
}

var config = &Config{
	Hosts:   make(map[string]struct{}),
	PathRules: make([]PathRule, 0),
}

// 生成根证书
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

// 生成域名证书
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
	// 读取hosts文件
	if err := parseHosts("/dksoft/conf/hosts"); err != nil {
		return err
	}

	// 读取url.cfg文件
	if err := parseUrlConfig("/dksoft/conf/url.cfg"); err != nil {
		return err
	}

	// 生成根证书
	caCert, caPrivKey, err := generateRootCA()
	if err != nil {
		return fmt.Errorf("生成CA证书失败: %v", err)
	}
	config.caCert = caCert
	config.caPrivKey = caPrivKey

	// 排序规则：特定域名优先，路径长的优先
	sort.Slice(config.PathRules, func(i, j int) bool {
		if config.PathRules[i].Host != "" && config.PathRules[j].Host == "" {
			return true
		}
		return len(config.PathRules[i].Path) > len(config.PathRules[j].Path)
	})

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

		// 解析URL模式
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

		// 处理文件路径
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

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// 检查白名单
	if _, ok := config.Hosts[r.Host]; !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "503 Service Unavailable")
		return
	}

	// 遍历规则寻找匹配项
	var targetFile string
	for _, rule := range config.PathRules {
		// 匹配域名
		if rule.Host != "" && rule.Host != r.Host {
			continue
		}

		// 精确匹配路径
		if r.URL.Path == rule.Path {
			targetFile = rule.FilePath
			break
		}
	}

	if targetFile == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// 读取文件
	content, err := os.ReadFile(targetFile)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// 返回响应
	w.Header().Set("Content-Type", getContentType(targetFile))
	w.WriteHeader(http.StatusOK)
	w.Write(content)
	
	log.Printf("[%s]%s --- 成功返回", r.Host, r.URL.Path)
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