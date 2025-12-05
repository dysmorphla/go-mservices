package servicehttp

import (
	"net/http"
)

func PingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Response " + r.RemoteAddr))
}

func RemoveHandler(w http.ResponseWriter, r *http.Request) {

}
