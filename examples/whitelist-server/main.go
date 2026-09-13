package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/aileron-projects/go-ipfilter"
)

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}

	// NG >>> curl --interface 127.0.0.1 http://localhost:8080
	// OK >>> curl --interface 127.0.0.2 http://localhost:8080
	// OK >>> curl --interface 127.0.0.3 http://localhost:8080
	ln, err = ipfilter.WhitelistListener(ln, "127.0.0.2", "127.0.0.3")
	if err != nil {
		panic(err)
	}

	svr := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Hello Gopher!!")
		}),
	}

	log.Println("server starting at ", ln.Addr().String())
	if err := svr.Serve(ln); err != nil {
		panic(err)
	}
}
