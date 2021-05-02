package tcp

import (
	"io"
	"log"
	"net"
	"os"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	//"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	//"bytes"
	"encoding/base64"
	"time"
	randMath "math/rand"
	"bufio"
	//"hash"
)

// Progress indicates transfer status
type Progress struct {
	bytes uint64
}

func tcp_con_handle(params ...net.Conn) {
	con := params[0]
	if len(params) == 1 {
		chan_to_remote := stream_copy(os.Stdin, con, true, false, "cli->stdin->proxy(Encrypt)")
		chan_to_stdout := stream_copy(con, os.Stdout, false, true, "cli->proxy->stdout(Decrypt)")
		select {
		case <-chan_to_stdout:
			log.Println("Remote connection is closed")
		case <-chan_to_remote:
			log.Println("Local program is terminated")
		}
	}else{
		proxy_con := params[1]
		chan_to_stdout := stream_copy(con, proxy_con, false, false, "serv->host->proxy(Decrypt)")
		chan_to_remote := stream_copy(proxy_con, con, true, false, "serv->proxy->host(Encrypt)")
		select {
		case <-chan_to_stdout:
			log.Println("Remote connection is closed")
		case <-chan_to_remote:
			log.Println("Local program is terminated")
		}
	}
	/*select {
	case <-chan_to_stdout:
		log.Println("Remote connection is closed")
	case <-chan_to_remote:
		log.Println("Local program is terminated")
	}*/
}

func genSalt() string {
	saltBytes := make([]byte, 8)
	randMath.Seed(time.Now().UnixNano())
	randMath.Read(saltBytes)
	return base64.StdEncoding.EncodeToString(saltBytes)
}


// Performs copy operation between streams: os and tcp streams
func stream_copy(src io.Reader, dst io.Writer,encrypt bool, flush bool, detail string) <-chan int {
	buf_dst := bufio.NewWriter(dst)
	buf_src := bufio.NewReader(src)
	sync_channel := make(chan int)
	go func() {
		defer func() {
			if con, ok := dst.(net.Conn); ok {
				con.Close()
				log.Printf("Connection from %v is closed\n", con.RemoteAddr())
			}
			sync_channel <- 0 // Notify that processing is finished
		}()
		for {
			buf := make([]byte, 2024)
			if encrypt {
				buf = make([]byte, 1024)
			}
			var nBytes int
			var err error
			nBytes, err = buf_src.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %s\n", err)
				}/*else{
					log.Println("Error in Read: %s\n",err)
				}*/
				break
			}
			if encrypt{
				salt := make([]byte, 8)
				key := pbkdf2.Key([]byte("aadil") , salt, 4096, 32, sha256.New)
				block, err := aes.NewCipher(key)
				if err != nil {
					log.Fatalf(err.Error())
				}
				aesGCM, err := cipher.NewGCM(block)
				if err != nil {
					log.Fatalf(err.Error())
				}
				nonce := make([]byte, aesGCM.NonceSize())
				_, err = rand.Read(nonce)
				if err != nil {
					log.Fatalf(err.Error())
				}
				ciphertext := aesGCM.Seal(nonce, nonce, buf[:nBytes], nil)
				_, err = buf_dst.Write(ciphertext)
				if err != nil {
					log.Fatalf("Write error: %s\n", err)
				}
			}else{
				salt := make([]byte, 8)
				key := pbkdf2.Key([]byte("aadil") , salt, 4096, 32, sha256.New)
				block, err := aes.NewCipher(key)
				if err != nil {
					log.Fatalf(err.Error())
				}

				aesGCM, err := cipher.NewGCM(block)
				nonce_size := aesGCM.NonceSize()

				if err != nil {
					log.Fatalf(err.Error())
				}
				if nBytes < aesGCM.NonceSize(){
					log.Fatalf(err.Error())
				}
				plaintext, err := aesGCM.Open(nil, buf[:nonce_size], buf[nonce_size:nBytes], nil)
				if err != nil {
					log.Fatalf(err.Error())
				}
				_, err = buf_dst.Write(plaintext)
				if err != nil {
					log.Fatalf("Write error: %s\n", err)
				}

			}
			err = buf_dst.Flush()
			if err != nil{
				log.Fatalf("Flush Error: %s\n", err)
			}

		}
	}()
	return sync_channel
}


// StartServer starts TCP listener
func StartServer(proto string, port string, listen_port string, host string) {
	//connect_to_proxy := true
	ln, err := net.Listen(proto, listen_port)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Listening on", proto+listen_port)
	//var proxy_con net.Conn
	for{
		log.Println("Waiting for new connection")
		con, err := ln.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("[%s]: Connection has been opened for client\n", con.RemoteAddr())

		//if connect_to_proxy {
			proxy_con, err := net.Dial(proto, host+port)
			if err != nil {
				log.Fatalln(err)
			}
			log.Printf("Proxy Connected")
			//connect_to_proxy = false
		//
		go tcp_con_handle(con, proxy_con)
	}
}

// StartClient starts TCP connector
func StartClient(proto string, host string, port string) {
	con, err := net.Dial(proto, host+port)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Connected to", host+port)
	tcp_con_handle(con)
}
