package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	golog "log"

	"github.com/dschp/go-msgauth/dkim"
	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

const LineFeed = "\r\n"

var log = golog.New(os.Stderr, "", 0)
var messageMap = make(map[string][]string)
var signingTable []SigningMatch

type SessionData struct {
	msgId string
	from  string
}

type SigningMatch struct {
	pattern  string
	domain   string
	selector string
	key      crypto.Signer
}

const debug = false

var signingHeaders = []string{"Date", "From", "To", "Subject", "Reply-To"}

func initSigningTable() {
	addSigningEntry("@example.com", "example.com", "selector", "/path/to/keyfile")
}

func addSigningEntry(pattern, domain, selector, filepath string) {
	log.Printf("Loading %s...\n", filepath)

	keyPem, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal("Failed to read file: ", err)
	}

	block, rest := pem.Decode(keyPem)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("Failed to decode PEM private key")
	}
	keyP, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Loaded a %T, with remaining data: %q\n", keyP, rest)
	log.Printf("Successfully initialized: %s %s %s %s", pattern, domain, selector, filepath)

	var key crypto.Signer
	switch v := keyP.(type) {
	case ed25519.PrivateKey:
		key = v
	case *rsa.PrivateKey:
		key = v
	default:
		log.Fatal("Can't load private key.")
	}

	signingTable = append(signingTable, SigningMatch{
		pattern:  pattern,
		domain:   domain,
		selector: selector,
		key:      key,
	})
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

func filterDataLineCb(timestamp time.Time, session filter.Session, line string) []string {
	if debug {
		log.Printf("%s: filter-data-line: %s\n", session, line)
	}
	data := session.Get().(*SessionData)

	if data.msgId == "" {
		return []string{line}
	}

	msg, ok := messageMap[data.msgId]
	if !ok {
		log.Fatal("Error: filter-data-line: %s (%s) message doens't exist\n", session, data.msgId)
	}

	if line != "." {
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		messageMap[data.msgId] = append(msg, line)
		return nil
	} else {
		strMsg := strings.Join(msg, LineFeed)

		m, err := mail.ReadMessage(strings.NewReader(strMsg))
		if err != nil {
			log.Println(err)
			return append(msg, ".")
		}
		hdr := &m.Header

		sh := []string{}
		for _, h := range signingHeaders {
			if hdr.Get(h) != "" {
				sh = append(sh, h)
			}
		}

		buf := bytes.NewBufferString(strMsg)
		for _, s := range signingTable {
			if !strings.HasSuffix(data.from, s.pattern) {
				continue
			}

			options := dkim.SignOptions{
				Domain:     s.domain,
				Selector:   s.selector,
				Signer:     s.key,
				HeaderKeys: sh,
			}

			var b2 bytes.Buffer
			if err := dkim.Sign(&b2, buf, &options); err == nil {
				log.Printf("Message signed with: d=%s, s=%s", s.domain, s.selector)
			} else {
				log.Println(err)
			}
			buf = &b2
		}

		signed := buf.String()
		if debug {
			msgFile := fmt.Sprintf("/tmp/mail-%s-%s", session, data.msgId)
			if err := os.WriteFile(msgFile, []byte(signed), 0666); err == nil {
				log.Printf("Signed message written to: %s\n", msgFile)
			} else {
				log.Println(err)
			}
		}
		lines := strings.Split(signed, LineFeed)

		finalMsg := make([]string, 0, len(lines))
		for _, l := range lines {
			if strings.HasPrefix(l, ".") {
				l = "." + l
			}
			finalMsg = append(finalMsg, l)
		}
		return append(finalMsg, ".")
	}
}

func main() {
	initSigningTable()

	filter.Init()

	filter.SMTP_IN.SessionAllocator(func() filter.SessionData {
		return &SessionData{}
	})

	filter.SMTP_IN.OnTxMail(txMailCb)
	filter.SMTP_IN.OnTxBegin(txBeginCb)
	filter.SMTP_IN.OnTxReset(txResetCb)
	filter.SMTP_IN.OnTxRollback(txRollbackCb)

	filter.SMTP_IN.DataLineRequest(filterDataLineCb)

	filter.Dispatch()
}
