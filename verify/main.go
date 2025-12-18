package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	golog "log"

	"blitiri.com.ar/go/spf"
	"github.com/dschp/go-msgauth/dkim"
	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

const LineFeed = "\r\n"

var log = golog.New(os.Stderr, "", 0)
var messageMap = make(map[string][]string)
var dbgTable map[string]string

var verifyOptions = dkim.VerifyOptions{
	LookupTXT: lookupTXT,
}

type SessionData struct {
	msgId string
	ip    net.IP
	from  string
	helo  string
}

const debug = false

var hostname = "example.com"

func initDebugTable() {
}

func addEntry(filepath, domain, selector string) {
	log.Printf("addEntry: %s %s %s\n", filepath, domain, selector)
	pubPem, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}
	block, rest := pem.Decode(pubPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("Failed to decode PEM public key")
	}
	pubP, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Loaded a %T, with remaining data: %q\n", pubP, rest)

	var k string
	var bs []byte
	switch v := pubP.(type) {
	case *rsa.PublicKey:
		k = "rsa"
		bs = block.Bytes
	case ed25519.PublicKey:
		k = "ed25519"
		bs = v
	default:
		log.Fatal("Can't load private key.")
	}

	pub64 := base64.StdEncoding.EncodeToString(bs)
	txt := "v=DKIM1; k=" + k + "; p=" + pub64
	log.Println(txt)

	dbgTable[selector+"._domainkey."+domain] = txt
}

func lookupTXT(domain string) ([]string, error) {
	log.Printf("LookupTXT: %s\n", domain)
	if dbgTable != nil {
		txt, ok := dbgTable[domain]
		if ok {
			return []string{txt}, nil
		}
	}
	rs, err := net.LookupTXT(domain)
	for _, r := range rs {
		log.Printf("%s\n", r)
	}
	return rs, err
}

func linkConnectCb(timestamp time.Time, session filter.Session, rdns string, fcrdns string, src net.Addr, dest net.Addr) {
	log.Printf("%s: link-connect: %s|%s|%s|%s\n", session, rdns, fcrdns, src, dest)
	data := session.Get().(*SessionData)

	if host, _, err := net.SplitHostPort(src.String()); err == nil {
		data.ip = net.ParseIP(host)
	} else {
		log.Println("Error splitting host and port:", err)
		data.ip = nil
	}
}

func linkIdentifyCb(timestamp time.Time, session filter.Session, method string, hostname string) {
	log.Printf("%s: link-identify: %s|%s\n", session, method, hostname)
	data := session.Get().(*SessionData)
	data.helo = hostname
}

func txMailCb(timestamp time.Time, session filter.Session, messageId string, result string, from string) {
	log.Printf("%s: tx-mail: %s|%s|%s\n", session, messageId, result, from)
	data := session.Get().(*SessionData)
	data.from = from
}

func txBeginCb(timestamp time.Time, session filter.Session, messageId string) {
	log.Printf("%s: tx-begin: %s\n", session, messageId)
	data := session.Get().(*SessionData)
	data.msgId = messageId
	messageMap[messageId] = []string{}
}

func txResetCb(timestamp time.Time, session filter.Session, messageId string) {
	log.Printf("%s: tx-reset: %s\n", session, messageId)
	data := session.Get().(*SessionData)
	data.msgId = ""
	delete(messageMap, messageId)
}

func txRollbackCb(timestamp time.Time, session filter.Session, messageId string) {
	log.Printf("%s: tx-rollback: %s\n", session, messageId)
	data := session.Get().(*SessionData)
	data.msgId = ""
	delete(messageMap, messageId)
}

func checkSPF(ip net.IP, from, helo string) string {
	parts := strings.Split(from, "@")
	if ip != nil && len(parts) == 2 {
		domain := parts[1]
		if domain != "" {
			h := ""
			if r, err := spf.CheckHostWithSender(ip, helo, from); err == nil {
				h = fmt.Sprintf("\tspf=%s (sender IP is %s) smtp.mailfrom=%s helo=%s;", r, ip, from, helo)
			} else {
				h = fmt.Sprintf("\tspf=%s (sender IP is %s) smtp.mailfrom=%s helo=%s (%s);", r, ip, from, helo, err)
			}
			log.Printf(h[1 : len(h)-1])
			return h
		}

	} else {
		log.Printf("Error: email address is invalid: %s\n", from)
	}
	return ""
}

func verifyDKIM(message, msgId string) []string {
	hdrs := []string{}

	r := strings.NewReader(message)
	verifications, err := dkim.VerifyWithOptions(r, &verifyOptions)
	if err != nil {
		log.Println(err)
	} else {
		for _, v := range verifications {
			var h string
			if v.Err == nil {
				h = fmt.Sprintf("\tdkim=pass (d=%s, i=%s, s=%s);", v.Domain, v.Identifier, v.Selector)
			} else {
				h = fmt.Sprintf("\tdkim=fail (d=%s, i=%s, s=%s) %s;", v.Domain, v.Identifier, v.Selector, v.Err)

				msgFile := "/tmp/mail-" + msgId
				if err := os.WriteFile(msgFile, []byte(message), 0666); err == nil {
					log.Printf("Message with dkim=fail written to: %s\n", msgFile)
				} else {
					log.Println(err)
				}
			}
			log.Printf(h[1 : len(h)-1])
			hdrs = append(hdrs, h)
		}
	}

	return hdrs
}

func filterDataLineCb(timestamp time.Time, session filter.Session, line string) []string {
	if debug {
		log.Printf("%s: filter-data-line: %s\n", session, line)
	}
	data := session.Get().(*SessionData)

	if data.msgId == "" {
		log.Printf("Error: filter-data-line: %s (%s) message id is empty\n", session, data.msgId)
		return []string{line}
	}

	msg, ok := messageMap[data.msgId]
	if !ok {
		log.Printf("Error: filter-data-line: %s (%s) message doens't exist\n", session, data.msgId)
		return []string{line}
	}

	if line != "." {
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		messageMap[data.msgId] = append(msg, line)
		return nil
	} else {
		strMsg := strings.Join(msg, LineFeed)
		authHdrs := []string{}

		if hdr := checkSPF(data.ip, data.from, data.helo); hdr != "" {
			authHdrs = append(authHdrs, hdr)
		}
		if hdrs := verifyDKIM(strMsg, data.msgId); len(hdrs) > 0 {
			authHdrs = append(authHdrs, hdrs...)
		}

		finalMsg := make([]string, 0, len(authHdrs)+len(msg))
		if len(authHdrs) > 0 {
			finalMsg = append(finalMsg, fmt.Sprintf("Authentication-Results: %s;", hostname))
			finalMsg = append(finalMsg, authHdrs...)
		}
		for _, l := range msg {
			if strings.HasPrefix(l, ".") {
				l = "." + l
			}
			finalMsg = append(finalMsg, l)
		}
		return append(finalMsg, ".")
	}
}

func main() {
	if hostname == "" {
		hn, err := os.Hostname()
		if err != nil {
			log.Fatal(err)
		}
		hostname = hn
	}

	initDebugTable()

	filter.Init()

	filter.SMTP_IN.SessionAllocator(func() filter.SessionData {
		return &SessionData{}
	})

	filter.SMTP_IN.OnLinkConnect(linkConnectCb)
	filter.SMTP_IN.OnLinkIdentify(linkIdentifyCb)

	filter.SMTP_IN.OnTxMail(txMailCb)
	filter.SMTP_IN.OnTxBegin(txBeginCb)
	filter.SMTP_IN.OnTxReset(txResetCb)
	filter.SMTP_IN.OnTxRollback(txRollbackCb)

	filter.SMTP_IN.DataLineRequest(filterDataLineCb)

	filter.Dispatch()
}
