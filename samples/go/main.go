// Bilerek açıklı demo hedefi — çalıştırmayın.
package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

func lookup(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("nslookup", host).Output()
	w.Write(out)
}

func user(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	rows, _ := db.Query("SELECT name FROM users WHERE id = " + id)
	defer rows.Close()
}

func main() {
	http.HandleFunc("/lookup", lookup)
	http.HandleFunc("/user", user)
	http.ListenAndServe(":8080", nil)
}
