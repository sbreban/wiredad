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

type Device struct {
	Id      int
	Name    string
	MacAddr string
	IpAddr  string
}

type Devices []Device

type Domain struct {
	Id       int
	Name     string
	Domain   string
	Block    int
}

type Domains []Domain

type User struct {
	Id       int
	Username string
	Password string
	Admin	 int
}

type Users []User

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var userJson User
	json.NewDecoder(r.Body).Decode(&userJson)
	fmt.Println(userJson)

	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select id, username, password, admin from users where username = ? and password = ?", userJson.Username, userJson.Password)
	checkError(err)
	defer rows.Close()
	var userDb *User
	for rows.Next() {
		var id int
		var username string
		var password string
		var admin int

		err = rows.Scan(&id, &username, &password, &admin)
		checkError(err)
		userDb = &User{Id:id, Username:username, Password:password, Admin:admin}
	}
	err = rows.Err()
	checkError(err)

	if userDb != nil {
		json.NewEncoder(w).Encode(userDb)
		json.NewEncoder(os.Stdout).Encode(userDb)
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Println(params)

	rows, err := db.Query("select u.id, u.username from users u where u.admin = ?", params["userId"])
	checkError(err)
	defer rows.Close()
	var users Users
	for rows.Next() {
		var id int
		var name string

		err = rows.Scan(&id, &name)
		checkError(err)
		fmt.Println(id, name)
		user := User{Id:id, Username:name}
		users = append(users, user)
	}
	err = rows.Err()
	checkError(err)
	json.NewEncoder(w).Encode(users)
	json.NewEncoder(os.Stdout).Encode(users)
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var userJson User
	json.NewDecoder(r.Body).Decode(&userJson)
	fmt.Printf("New user: %v\n", userJson)

	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	stmt, err := db.Prepare("insert into users(username, password, admin) values (?, ?, ?)")
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(userJson.Username, userJson.Password, userJson.Admin)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Affected rows: %d\n", affected)
}


func devicesHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Printf("Clients param: %v\n", params)

	rows, err := db.Query("select d.id, d.name, d.mac_addr, d.ip_addr from devices d inner join user_device ud on d.id = ud.device_id where ud.user_id = ?", params["userId"])
	checkError(err)
	defer rows.Close()
	var devices Devices
	for rows.Next() {
		var id int
		var name string
		var macAddr string
		var ipAddr string

		err = rows.Scan(&id, &name, &macAddr, &ipAddr)
		checkError(err)
		fmt.Println(name, macAddr, ipAddr)
		device := Device{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr}
		devices = append(devices, device)
	}
	err = rows.Err()
	checkError(err)
	json.NewEncoder(w).Encode(devices)
	json.NewEncoder(os.Stdout).Encode(devices)
}

func registerDeviceHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Printf("Register device param: %v\n", params)

	var deviceJson Device
	json.NewDecoder(r.Body).Decode(&deviceJson)
	fmt.Printf("New device: %v\n", deviceJson)

	stmt, err := db.Prepare("insert into devices(name, mac_addr, ip_addr) VALUES (?, ?, ?)")
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(deviceJson.Name, deviceJson.MacAddr, deviceJson.IpAddr)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Insert device affected rows: %d\n", affected)

	rows, err := db.Query("select last_insert_rowid()")
	checkError(err)

	var deviceId int
	if rows.Next() {
		err = rows.Scan(&deviceId)
		checkError(err)
		fmt.Printf("Device id: %d\n", deviceId)
	}

	stmt, err = db.Prepare("insert into user_device(user_id, device_id) VALUES (?, ?)")
	checkError(err)

	tx, err = db.Begin()
	checkError(err)

	res, err = tx.Stmt(stmt).Exec(params["userId"], deviceId)
	checkError(err)

	affected, err = res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Insert device link affected rows: %d\n", affected)
}

func domainsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select d.id, d.name, d.domain, d.block from domains d")
	checkError(err)
	defer rows.Close()

	var netDomains Domains
	for rows.Next() {
		var id int
		var name string
		var domain string
		var block int

		err = rows.Scan(&id, &name, &domain, &block)
		checkError(err)
		fmt.Println(id, name, domain)
		domainElement := Domain{Id: id, Name: name, Domain: domain, Block: block}
		netDomains = append(netDomains, domainElement)
	}
	err = rows.Err()
	checkError(err)
	json.NewEncoder(w).Encode(netDomains)
	json.NewEncoder(os.Stdout).Encode(netDomains)
}

func addDomainHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	var domainJson Domain
	json.NewDecoder(r.Body).Decode(&domainJson)
	fmt.Printf("New domain: %v\n", domainJson)

	stmt, err := db.Prepare("insert into domains(name, domain, block) VALUES (?, ?, ?)")
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(domainJson.Name, domainJson.Domain, domainJson.Block)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Insert domain affected rows: %d\n", affected)
}

func deleteDomainHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Printf("Delete domain param: %v\n", params)

	domainId, err := strconv.Atoi(params["domainId"])
	checkError(err)

	changeBlockState(domainId, 0)

	stmt, err := db.Prepare("delete from domains where id = ?")
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(domainId)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Delete domain affected rows: %d\n", affected)
}

func editDomainHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	var domainJson Domain
	json.NewDecoder(r.Body).Decode(&domainJson)
	fmt.Printf("Edited domain: %v\n", domainJson)

	params := mux.Vars(r)
	fmt.Printf("Edit domain param: %v\n", params)

	domainId, err := strconv.Atoi(params["domainId"])
	checkError(err)

	changeBlockState(domainId, 0)

	stmt, err := db.Prepare("update domains set domain = ? where id = ?")
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(domainJson.Domain, domainId)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Edit domain affected rows: %d\n", affected)

	changeBlockState(domainId, domainJson.Block)
}


func getDomain(domainId int) Domain {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select d.id, d.name, d.domain, d.block from domains d where d.id = ? ", domainId)
	checkError(err)
	defer rows.Close()

	var netDomain Domain
	for rows.Next() {
		var id int
		var name string
		var domain string
		var block int

		err = rows.Scan(&id, &name, &domain, &block)
		checkError(err)
		netDomain = Domain{Id: id, Name: name, Domain: domain, Block: block}
		fmt.Printf("Domain: %v\n", netDomain)
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
	fmt.Printf("Domain block params: %v\n", params)

	stmt, err := db.Prepare("update domains set block = ? where id = ?")
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

	fmt.Printf("Domain block affected rows: %d\n", affected)

	changeBlockState(domainId, block)
}

func changeBlockState(domainId int, block int) {
	netDomain := getDomain(domainId)
	var cmd *exec.Cmd
	if block == 1 {
		cmd = exec.Command("pihole", "-wild", netDomain.Domain)
	} else {
		cmd = exec.Command("pihole", "-wild", "-d", netDomain.Domain)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
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
		"POST",
		"/login",
		loginHandler,
	},
	Route{
		"Users",
		"GET",
		"/users/{userId}",
		usersHandler,
	},
	Route{
		"AddUser",
		"POST",
		"/add_user",
		addUserHandler,
	},
	Route{
		"Devices",
		"GET",
		"/devices/{userId}",
		devicesHandler,
	},
	Route{
		"RegisterDevice",
		"POST",
		"/register_device/{userId}",
		registerDeviceHandler,
	},
	Route{
		"Domains",
		"GET",
		"/domains",
		domainsHandler,
	},
	Route{
		"AddDomain",
		"POST",
		"/add_domain",
		addDomainHandler,
	},
	Route{
		"DeleteDomain",
		"POST",
		"/delete_domain/{domainId}",
		deleteDomainHandler,
	},
	Route{
		"EditDomain",
		"POST",
		"/edit_domain/{domainId}",
		editDomainHandler,
	},
	Route{
		"BlockDomains",
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
