package tcp

import (
	"io"
	"log"
	"net"
	"os"
)

// Progress indicates transfer status
type Progress struct {
	bytes uint64
}

// TransferStreams launches two read-write goroutines and waits for signal from them
func TransferStreams(params ...net.Conn) {
	con := params[0]
	c := make(chan Progress)

	// Read from Reader and write to Writer until EOF
	copy := func(r io.ReadCloser, w io.WriteCloser) {
		defer func() {
			r.Close()
			w.Close()
		}()
		n, err := io.Copy(w, r)
		if err != nil {
			log.Printf("[%s]: ERROR: %s\n", con.RemoteAddr(), err)
		}
		c <- Progress{bytes: uint64(n)}
	}
	if len(params) == 1 {
		go copy(con, os.Stdout)
		go copy(os.Stdin, con)
	}else{
		proxy_con := params[1]
		go copy(con, proxy_con)
		go copy(proxy_con, con)
	}
	p := <-c
	log.Printf("[%s]: Connection has been closed by remote peer, %d bytes has been received\n", con.RemoteAddr(), p.bytes)
	p = <-c
	log.Printf("[%s]: Local peer has been stopped, %d bytes has been sent\n", con.RemoteAddr(), p.bytes)
}

// StartServer starts TCP listener
func StartServer(proto string, port string, listen_port string, host string) {
	ln, err := net.Listen(proto, listen_port)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Listening on", proto+listen_port)
	con, err := ln.Accept()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("[%s]: Connection has been opened\n", con.RemoteAddr())
	proxy_con, err := net.Dial(proto, host+port)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Proxy Connected")
	TransferStreams(con, proxy_con)
}

// StartClient starts TCP connector
func StartClient(proto string, host string, port string) {
	con, err := net.Dial(proto, host+port)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Connected to", host+port)
	TransferStreams(con)
}
