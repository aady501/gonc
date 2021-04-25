package main

import (
	"flag"

	"utils/tcp"
)

func main() {
	var host, port, proto,listen_port string
	//var listen bool
	flag.StringVar(&host, "host", "", "Remote host to connect, i.e. 127.0.0.1")
	flag.StringVar(&proto, "proto", "tcp", "TCP/UDP mode")
	flag.StringVar(&listen_port, "l", "", "Listen port")
	flag.StringVar(&port, "port", ":9999", "Port to listen on or connect to (prepended by colon), i.e. :9999")
	flag.Parse()

	switch proto {
	case "tcp":
		if listen_port != "" && host != "" {
			tcp.StartServer(proto, port, listen_port, host)
		} else if host != "" {
			tcp.StartClient(proto, host, port)
		} else {
			flag.Usage()
		}
	/*case "udp":
		if listen {
			udp.StartServer(proto, port)
		} else if host != "" {
			udp.StartClient(proto, host, port)
		} else {
			flag.Usage()
		}*/
	default:
		flag.Usage()
	}
}
