package servicehttp

import (
	"net/http"
)

func PingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Response " + r.RemoteAddr))
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

}

func ResetHandler(w http.ResponseWriter, r *http.Request) {

}
