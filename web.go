package main

import (
	"net/http"
	"log"
	"encoding/json"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"fmt"
	"os"
)

type NetClient struct {
	Name string
	MacAddr string
	IpAddr string
}

func clientsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("select name, mac_addr, ip_addr from clients")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var macAddr string
		var ipAddr string

		err = rows.Scan(&name, &macAddr, &ipAddr)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(name, macAddr, ipAddr)
		client := NetClient{Name:name, MacAddr:macAddr, IpAddr:ipAddr}

		json.NewEncoder(w).Encode(client)
		json.NewEncoder(os.Stdout).Encode(client)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/clients", clientsHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
