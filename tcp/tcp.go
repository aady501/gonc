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
		chan_to_stdout := stream_copy(con, os.Stdout, false, true)
		chan_to_remote := stream_copy(os.Stdin, con, true, false)
		select {
		case <-chan_to_stdout:
			log.Println("Remote connection is closed")
		case <-chan_to_remote:
			log.Println("Local program is terminated")
		}
	}else{
		proxy_con := params[1]
		chan_to_stdout := stream_copy(con, proxy_con, false, false)
		chan_to_remote := stream_copy(proxy_con, con, true, false)
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
func stream_copy(src io.Reader, dst io.Writer,encrypt bool, flush bool) <-chan int {
	buf_dst := bufio.NewWriter(dst)
	buf_src := bufio.NewReader(src)
	buf := make([]byte, 1024)
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
			//buf := make([]byte, 1024)
			var nBytes int
			var err error
			nBytes, err = buf_src.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %s\n", err)
				}else{
					log.Println("Error in Read: %s\n",err)
				}
			}
			if encrypt{
				//log.Println("In Encryption: ", buf, ", String: ", string(buf[:]))
				//salt := bytes.NewbufferString(genSalt()).Bytes()
				salt := make([]byte, 8)
				key := pbkdf2.Key([]byte("aadil") , salt, 4096, 32, sha256.New)
				//log.Println("key: ", key)
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
				//log.Println("Nonce: ",nonce)

				//output := make([]byte, aesGCM.NonceSize() + len(ciphertext))
				//copy(output[:len(nonce)], nonce)
				//copy(output[len(nonce):], ciphertext)

				_, err = buf_dst.Write(ciphertext)
				if err != nil {
					log.Fatalf("Write error: %s\n", err)
				}
					/*err = buf_dst.Flush()
					if err != nil{
						log.Fatalf("Flush Error: %s\n", err)
					}*/
				//log.Println("Encrypted ",ciphertext, ",", string(ciphertext[:]), "Length of ciphertext: ", len(ciphertext))
				log.Println("Before Encryption: ", string(buf[:nBytes]),"Encrypted: ", string(ciphertext[:]))
			}else{
				salt := make([]byte, 8)
				key := pbkdf2.Key([]byte("aadil") , salt, 4096, 32, sha256.New)
				//log.Println("Key: ", key)
				block, err := aes.NewCipher(key)
				if err != nil {
					log.Fatalf(err.Error())
				}

				aesGCM, err := cipher.NewGCM(block)
				nonce_size := aesGCM.NonceSize()
				//log.Println("NonceSize: ", aesGCM.NonceSize(), "nbytes=", nBytes)

				//log.Println("In Decryption: ", buf[nonce_size:nBytes], ", String: ", string(buf[:nBytes]))
				if err != nil {
					log.Fatalf(err.Error())
				}
				if nBytes < aesGCM.NonceSize(){
					log.Fatalf(err.Error())
				}
				plaintext, err := aesGCM.Open(nil, buf[:nonce_size], buf[aesGCM.NonceSize():nBytes], nil)
				if err != nil {
					log.Fatalf(err.Error())
				}
				_, err = buf_dst.Write(plaintext)
				if err != nil {
					log.Fatalf("Write error: %s\n", err)
				}
				/*if flush{
					err = buf_dst.Flush()
					if err != nil{
						log.Fatalf("Flush Error: %s\n", err)
					}
				}*/
				//log.Println("Decrypted: ", plaintext[:], ", ", string(plaintext[:]))
				log.Println("Before Decryption: " ,string(buf[:nBytes]),"Decrypted: ", string(plaintext[:]))
			}
		}
	}()
	return sync_channel
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
		//buf:=new(bytes.Buffer)
		//buf.ReadFrom(r)
		log.Printf("Hey is someone there")
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
	tcp_con_handle(con, proxy_con)
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
