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
	Id      int
	Name    string
	MacAddr string
	IpAddr  string
}

type NetClients []NetClient

type NetDomain struct {
	Id     int
	Name   string
	Domain string
}

type NetDomains []NetDomain

func clientsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("select id, name, mac_addr, ip_addr from clients")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	var netClients NetClients
	for rows.Next() {
		var id int
		var name string
		var macAddr string
		var ipAddr string

		err = rows.Scan(&id, &name, &macAddr, &ipAddr)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(name, macAddr, ipAddr)
		client := NetClient{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr}
		netClients = append(netClients, client)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode(netClients)
	json.NewEncoder(os.Stdout).Encode(netClients)
}

func domainsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("select id, name, domain from domains")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	var netDomains NetDomains
	for rows.Next() {
		var id int
		var name string
		var domain string

		err = rows.Scan(&id, &name, &domain)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(id, name, domain)
		domainElement := NetDomain{Id: id, Name: name, Domain: domain}
		netDomains = append(netDomains, domainElement)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode(netDomains)
	json.NewEncoder(os.Stdout).Encode(netDomains)
}

func main() {
	http.HandleFunc("/clients", clientsHandler)
	http.HandleFunc("/domains", domainsHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
