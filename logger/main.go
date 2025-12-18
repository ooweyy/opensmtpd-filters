package main

import (
	golog "log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

var log = golog.New(os.Stderr, "", 0)

const debug = false

type SessionData struct {
	ip net.Addr
}

func linkConnectCb(timestamp time.Time, session filter.Session, rdns string, fcrdns string, src net.Addr, dest net.Addr) {
	if debug {
		log.Printf("%s: link-connect: %s|%s|%s|%s\n", session, rdns, fcrdns, src, dest)
	}
	data := session.Get().(*SessionData)
	data.ip = src
}

func protocolClientCb(timestamp time.Time, session filter.Session, command string) {
	log.Printf("%s: protocol-client: %s\n", session, command)
}

func protocolServerCb(timestamp time.Time, session filter.Session, response string) {
	if strings.HasPrefix(response, "5") {
		data := session.Get().(*SessionData)
		log.Printf("%s: [%s] protocol-server: %s\n", session, data.ip, response)
	}
}

func main() {
	filter.Init()

	filter.SMTP_IN.SessionAllocator(func() filter.SessionData {
		return &SessionData{}
	})

	filter.SMTP_IN.OnLinkConnect(linkConnectCb)
	filter.SMTP_IN.OnProtocolClient(protocolClientCb)
	filter.SMTP_IN.OnProtocolServer(protocolServerCb)

	filter.Dispatch()
}
