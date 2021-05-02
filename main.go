package main

import (
	"flag"
	"log"
	"utils/tcp"
	"io/ioutil"
)

func main() {
	var host, port, listen_port, pwd_file string
	flag.StringVar(&listen_port, "l", "", "Listen port")
	flag.StringVar(&pwd_file, "p", "", "pwdfile")
	flag.Parse()
	if len(flag.Args()) == 2 {
		host = flag.Args()[0]
		port = flag.Args()[1]
	}else{
		flag.Usage()
		return
	}

	if listen_port != "" && host != "" && pwd_file != "" {
		password, err := ioutil.ReadFile(pwd_file)
		if err != nil {
			log.Println("Error in read file")
		}
		tcp.StartServer(":"+port, ":"+listen_port, host, string(password))
	} else if host != "" && pwd_file != "" {
		password, err := ioutil.ReadFile(pwd_file)
		if err != nil {
			log.Println("Error in read file")
		}
		tcp.StartClient(host, ":"+port, string(password))
	} else {
		flag.Usage()
	}
}
