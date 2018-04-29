package main

import (
	"net/http"
	"log"
	"encoding/json"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"fmt"
	"os"
	"github.com/gorilla/mux"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

type NetClient struct {
	Id      int
	Name    string
	MacAddr string
	IpAddr  string
}

type NetClients []NetClient

type NetDomain struct {
	Id       int
	ClientId int
	Name     string
	Domain   string
	Block    int
}

type NetDomains []NetDomain

func clientsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select id, name, mac_addr, ip_addr from clients")
	checkError(err)
	defer rows.Close()
	var netClients NetClients
	for rows.Next() {
		var id int
		var name string
		var macAddr string
		var ipAddr string

		err = rows.Scan(&id, &name, &macAddr, &ipAddr)
		checkError(err)
		fmt.Println(name, macAddr, ipAddr)
		client := NetClient{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr}
		netClients = append(netClients, client)
	}
	err = rows.Err()
	checkError(err)
	json.NewEncoder(w).Encode(netClients)
	json.NewEncoder(os.Stdout).Encode(netClients)
}

func clientDomainsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Println(params)

	rows, err := db.Query("select d.id, cd.client_id, d.name, d.domain, cd.block from domains d "+
		"inner join client_domain cd on cd.domain_id = d.id "+
		"where cd.client_id = ? ", params["clientId"])
	checkError(err)
	defer rows.Close()

	var netDomains NetDomains
	for rows.Next() {
		var id int
		var clientId int
		var name string
		var domain string
		var block int

		err = rows.Scan(&id, &clientId, &name, &domain, &block)
		checkError(err)
		fmt.Println(id, name, domain)
		domainElement := NetDomain{Id: id, ClientId: clientId, Name: name, Domain: domain, Block: block}
		netDomains = append(netDomains, domainElement)
	}
	err = rows.Err()
	checkError(err)
	json.NewEncoder(w).Encode(netDomains)
	json.NewEncoder(os.Stdout).Encode(netDomains)
}

func domainBlockHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Println(params)

	stmt, err := db.Prepare("update client_domain " +
		"set block = ? where domain_id = ?")
	checkError(err)

	res, err := stmt.Exec(params["domainId"], params["block"])
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	fmt.Println(affected)
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

var routes = Routes{
	Route{
		"Clients",
		"GET",
		"/clients",
		clientsHandler,
	},
	Route{
		"Domains",
		"GET",
		"/domains/{clientId}",
		clientDomainsHandler,
	},
	Route{
		"Domains",
		"POST",
		"/domains/{domainId}/{block}",
		domainBlockHandler,
	},
}

func main() {
	router := mux.NewRouter()
	for _, route := range routes {
		router.HandleFunc(route.Pattern, route.HandlerFunc).Methods(route.Method)
	}
	log.Fatal(http.ListenAndServe(":8080", router))
}
