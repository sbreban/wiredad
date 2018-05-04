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
	"strconv"
	"os/exec"
	"bytes"
	"github.com/dgrijalva/jwt-go"
	"github.com/auth0/go-jwt-middleware"
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "{'user':{'username':'ali','password':'sesame'}}")
	fmt.Print("{'user':{'username':'ali','password':'sesame'}}")
}

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

func getDomain(domainId int) NetDomain {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select d.id, cd.client_id, d.name, d.domain, cd.block from domains d "+
		"inner join client_domain cd on cd.domain_id = d.id "+
		"where cd.domain_id = ? ", domainId)
	checkError(err)
	defer rows.Close()

	var netDomain NetDomain
	for rows.Next() {
		var id int
		var clientId int
		var name string
		var domain string
		var block int

		err = rows.Scan(&id, &clientId, &name, &domain, &block)
		checkError(err)
		netDomain = NetDomain{Id: id, ClientId: clientId, Name: name, Domain: domain, Block: block}
		fmt.Printf("Domain: %v", netDomain)
	}
	err = rows.Err()
	checkError(err)

	return netDomain
}

func domainBlockHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Printf("Params: %v\n", params)

	stmt, err := db.Prepare("update client_domain " +
		"set block = ? where domain_id = ?")
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	domainId, err := strconv.Atoi(params["domainId"])
	checkError(err)

	block, err := strconv.Atoi(params["block"])
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(block, domainId)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Affected rows: %d\n", affected)

	netDomain := getDomain(domainId)

	var cmd *exec.Cmd
	if block == 1 {
		cmd = exec.Command("pihole", "-b", netDomain.Domain)
	} else {
		cmd = exec.Command("pihole", "-b", "-d", netDomain.Domain)
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	checkError(err)
	fmt.Println(out.String())
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

var routes = Routes{
	Route{
		"Login",
		"GET",
		"/login",
		loginHandler,
	},
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

func validateToken(tokenString string) {
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return secret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["sub"], claims["name"], claims["iat"])
	} else {
		fmt.Println(err)
	}
}

var secret = []byte("sesame")

func main() {
	var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	router := mux.NewRouter()
	for _, route := range routes {
		router.Handle(route.Pattern, jwtMiddleware.Handler(route.HandlerFunc)).Methods(route.Method)
	}
	log.Fatal(http.ListenAndServe(":8080", router))
}
