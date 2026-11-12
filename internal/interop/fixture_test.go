//go:build interop

package interop

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

const smsAuthority = "dypnsapi.aliyuncs.com"

// This helper is compiled only with the interop tag and runs in an owned fixture
// container. The distributed MemberID executable contains no fixture handlers.
func TestFixture(t *testing.T) {
	switch os.Getenv("MEMBERID_INTEROP_HELPER") {
	case "prepare":
		if err := os.Chmod("/configuration", 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown("/configuration", 65532, 65532); err != nil {
			t.Fatal(err)
		}
	case "edge":
		upstream, err := url.Parse("http://127.0.0.1:18082")
		if err != nil {
			t.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		director := proxy.Director
		proxy.Director = func(r *http.Request) {
			director(r)
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		server := &http.Server{Addr: "0.0.0.0:18080", Handler: proxy, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		if err := server.ListenAndServeTLS("/fixture-data/issuer.pem", "/fixture-data/issuer-key.pem"); err != nil {
			t.Fatal("fixture TLS endpoint stopped")
		}
	case "sms":
		certificate, err := tls.LoadX509KeyPair("/fixture-data/sms.pem", "/fixture-data/sms-key.pem")
		if err != nil {
			t.Fatal("test TLS material unavailable")
		}
		server := &http.Server{Addr: "127.0.0.1:18081", ReadHeaderTimeout: 5 * time.Second}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != smsAuthority+":443" {
				http.Error(w, "fixture destination refused", http.StatusForbidden)
				return
			}
			connection, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			if buffered.Flush() != nil {
				return
			}
			secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
			if secured.HandshakeContext(r.Context()) != nil {
				return
			}
			request, err := http.ReadRequest(bufio.NewReader(secured))
			if err != nil {
				return
			}
			defer request.Body.Close()
			var parameters struct{ Code string }
			valid := request.Method == "POST" && request.Host == smsAuthority && request.Header.Get("x-acs-action") == "SendSmsVerifyCode" && request.URL.Query().Get("PhoneNumber") == "19900000001" && json.Unmarshal([]byte(request.URL.Query().Get("TemplateParam")), &parameters) == nil && regexp.MustCompile(`^[0-9]{6}$`).MatchString(parameters.Code)
			if !valid {
				_, _ = fmt.Fprint(secured, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				return
			}
			if err := writeFixtureJSON("/fixture-data/sms.json", map[string]string{"code": parameters.Code}); err != nil {
				return
			}
			body := `{"Code":"OK","Success":true}`
			_, _ = fmt.Fprintf(secured, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		})
		if err := os.WriteFile("/fixture-data/sms-ready", []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := server.ListenAndServe(); err != nil {
			t.Fatal("SMS fixture stopped")
		}
	default:
		t.Skip("separate fixture process only")
	}
}

func writeFixtureJSON(file string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := file + ".next"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, file)
}

func createFixtureCertificate(t *testing.T, directory, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "MemberID synthetic " + name + " fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if name == "sms" {
		certificate.DNSNames = []string{smsAuthority}
	} else {
		certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		certificate.PermittedDNSDomainsCritical = true
		certificate.PermittedIPRanges = []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)}}
		certificate.ExcludedDNSDomains = []string{""}
	}
	encoded, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for file, block := range map[string]*pem.Block{name + ".pem": {Type: "CERTIFICATE", Bytes: encoded}, name + "-key.pem": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}} {
		mode := os.FileMode(0600)
		if file == name+".pem" {
			mode = 0644
		}
		if err := os.WriteFile(filepath.Join(directory, file), pem.EncodeToMemory(block), mode); err != nil {
			t.Fatal(err)
		}
	}
}
