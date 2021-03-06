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
	"io/ioutil"
	"strings"
	"net"
	"time"
	"bufio"
	"github.com/robfig/cron"
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
	Block   int
}

type Devices []Device

type Domain struct {
	Id     int
	Name   string
	Domain string
	Block  int
}

type Domains []Domain

type User struct {
	Id         int
	Name       string
	Username   string
	Password   string
	Token      string
	Admin      int
	AgeBracket string
}

type Users []User

type DeviceQueryStatistic struct {
	Position int
	Queries  int
	Ip       string
	Name     string
}

type DeviceQueryStatistics []DeviceQueryStatistic

type DomainQueryStatistic struct {
	Position int
	Queries  int
	Name     string
}

type DomainQueryStatistics []DomainQueryStatistic

type DeviceBlock struct {
	DeviceId int
	FromTime string
	ToTime   string
	Block    int
}

type UserReward struct {
	DeviceMAC     string
	RewardMinutes int
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var userJson User
	json.NewDecoder(r.Body).Decode(&userJson)
	log.Println(userJson)

	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select id, name, username, password, token, admin from users where username = ? and password = ?", userJson.Username, userJson.Password)
	checkError(err)
	defer rows.Close()

	var userDb *User
	for rows.Next() {
		var id int
		var name string
		var username string
		var password string
		var token string
		var admin int

		err = rows.Scan(&id, &name, &username, &password, &token, &admin)
		checkError(err)
		userDb = &User{Id: id, Name: name, Username: username, Password: password, Token: token, Admin: admin}
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
	log.Println(params)

	rows, err := db.Query("select u.id, u.name, u.username, a.name from users u inner join user_age_bracket b on u.id = b.user_id inner join age_brackets a on b.bracket_id = a.id where u.admin = ?", params["userId"])
	checkError(err)
	defer rows.Close()

	var users Users
	for rows.Next() {
		var id int
		var name string
		var username string
		var ageBracket string

		err = rows.Scan(&id, &name, &username, &ageBracket)
		checkError(err)
		log.Println(id, username)
		user := User{Id: id, Name: name, Username: username, AgeBracket: ageBracket}
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
	log.Printf("New user: %v\n", userJson)

	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	stmt, err := db.Prepare("insert into users(name, username, password, admin) values (?, ?, ?, ?)")
	checkError(err)
	defer stmt.Close()

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(userJson.Name, userJson.Username, userJson.Password, userJson.Admin)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	lastInsertId, err := res.LastInsertId()
	checkError(err)

	tx.Commit()

	log.Printf("Add user affected rows: %d insert id: %d\n", affected, lastInsertId)

	ageBracketId := getAgeBracketId(userJson.AgeBracket)

	log.Printf("Insert age bracket ids: %d %d\n", lastInsertId, ageBracketId)

	stmt, err = db.Prepare("insert into user_age_bracket(user_id, bracket_id) values (?, ?)")
	checkError(err)
	defer stmt.Close()

	tx, err = db.Begin()
	checkError(err)

	res, err = tx.Stmt(stmt).Exec(lastInsertId, ageBracketId)
	checkError(err)

	affected, err = res.RowsAffected()
	checkError(err)

	tx.Commit()

	log.Printf("Insert bracket affected rows: %d\n", affected)
}

func getAgeBracketId(ageBracket string) int {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select id from age_brackets where name = ? ", ageBracket)
	checkError(err)
	defer rows.Close()

	var ageBracketId int
	for rows.Next() {
		err = rows.Scan(&ageBracketId)
		checkError(err)
	}
	err = rows.Err()
	checkError(err)

	return ageBracketId
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Printf("Devices param: %v\n", params)

	rows, err := db.Query("select d.id, d.name, d.mac_addr, d.ip_addr, db.block from devices d inner join user_device ud on d.id = ud.device_id left join device_block db on d.id = db.device_id where ud.user_id = ?", params["userId"])
	checkError(err)
	defer rows.Close()

	var devices Devices
	for rows.Next() {
		var id int
		var name string
		var macAddr string
		var ipAddr string
		var blockNull sql.NullInt64

		err = rows.Scan(&id, &name, &macAddr, &ipAddr, &blockNull)
		checkError(err)
		log.Printf("Load device: %s %s %s %v\n", name, macAddr, ipAddr, blockNull)
		var device Device
		if blockNull.Valid {
			device = Device{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr, Block:int(blockNull.Int64)}
		} else {
			device = Device{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr, Block:0}
		}
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
	log.Printf("Register device param: %v\n", params)

	var deviceJson Device
	json.NewDecoder(r.Body).Decode(&deviceJson)
	fmt.Printf("New device: %v\n", deviceJson)

	stmt, err := db.Prepare("insert into devices(name, mac_addr, ip_addr) VALUES (?, ?, ?)")
	checkError(err)
	defer stmt.Close()

	tx, err := db.Begin()
	checkError(err)

	arr := strings.Split(deviceJson.MacAddr, ":")
	if len(arr) != 6 {

		log.Printf("Invalid MAC address")

	} else {

		res, err := tx.Stmt(stmt).Exec(deviceJson.Name, deviceJson.MacAddr, deviceJson.IpAddr)
		checkError(err)

		affected, err := res.RowsAffected()
		checkError(err)

		tx.Commit()

		log.Printf("Insert device affected rows: %d\n", affected)

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
		defer stmt.Close()

		tx, err = db.Begin()
		checkError(err)

		res, err = tx.Stmt(stmt).Exec(params["userId"], deviceId)
		checkError(err)

		affected, err = res.RowsAffected()
		checkError(err)

		tx.Commit()

		addDeviceBlock(deviceId)

		log.Printf("Insert device link affected rows: %d\n", affected)
	}
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
	log.Printf("New domain: %v\n", domainJson)

	stmt, err := db.Prepare("insert into domains(name, domain, block) VALUES (?, ?, ?)")
	checkError(err)
	defer stmt.Close()

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(domainJson.Name, domainJson.Domain, domainJson.Block)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	log.Printf("Insert domain affected rows: %d\n", affected)
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
	defer stmt.Close()

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
	defer stmt.Close()

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

func getDevice(deviceId int) Device {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select d.id, d.name, d.mac_addr, d.ip_addr from devices d where d.id = ? ", deviceId)
	checkError(err)
	defer rows.Close()

	var device Device
	for rows.Next() {
		var id int
		var name string
		var macAddr string
		var ipAddr string

		err = rows.Scan(&id, &name, &macAddr, &ipAddr)
		checkError(err)
		device = Device{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr}
		fmt.Printf("Device: %v\n", device)
	}
	err = rows.Err()
	checkError(err)

	return device
}

func getDeviceByIP(deviceIP string) *Device {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select d.id, d.name, d.mac_addr, d.ip_addr from devices d where d.ip_addr = ? ", deviceIP)
	checkError(err)
	defer rows.Close()

	var device *Device
	for rows.Next() {
		var id int
		var name string
		var macAddr string
		var ipAddr string

		err = rows.Scan(&id, &name, &macAddr, &ipAddr)
		checkError(err)
		device = &Device{Id: id, Name: name, MacAddr: macAddr, IpAddr: ipAddr}
		fmt.Printf("Device: %v\n", device)
	}
	err = rows.Err()
	checkError(err)

	return device
}

func domainBlockHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	fmt.Printf("Domain block params: %v\n", params)

	stmt, err := db.Prepare("update domains set block = ? where id = ?")
	checkError(err)
	defer stmt.Close()

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

	log.Printf("Domain block affected rows: %d\n", affected)

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
	log.Println(out.String())
}

func checkDeviceRegistration(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	fmt.Println("Check device registration")
	var macAddr string
	content, err := ioutil.ReadAll(r.Body)
	checkError(err)
	macAddr = string(content)
	fmt.Printf("Register mac: %s\n", macAddr)

	rows, err := db.Query("select id from devices where mac_addr = ? ", macAddr)
	checkError(err)
	defer rows.Close()

	var response string
	if rows.Next() {
		response = "PRESENT"
	} else {
		response = "MISSING"
	}
	err = rows.Err()
	checkError(err)

	w.Write([]byte(response))
}

func deviceBlockHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	log.Printf("Device block params: %v\n", params)

	deviceId, err := strconv.Atoi(params["deviceId"])
	checkError(err)

	block, err := strconv.Atoi(params["block"])
	checkError(err)

	deviceBlock := getDeviceBlock(deviceId)
	if deviceBlock == nil {
		addDeviceBlock(deviceId)
		deviceBlock = getDeviceBlock(deviceId)
	}

	if block != deviceBlock.Block {
		blockDevice(deviceId, block)
	} else {
		log.Printf("Device already in the blocking state: %d\n", block)
	}
}

func getDeviceBlockHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	params := mux.Vars(r)
	log.Printf("Get device block params: %v\n", params)

	deviceId, err := strconv.Atoi(params["deviceId"])
	checkError(err)

	deviceBlock := getDeviceBlock(deviceId)
	if deviceBlock == nil {
		addDeviceBlock(deviceId)
		deviceBlock = getDeviceBlock(deviceId)
	}

	json.NewEncoder(w).Encode(deviceBlock)
	log.Printf("Get device block result: %v\n", deviceBlock)
}

func setDeviceBlockHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	var deviceBlockJson DeviceBlock
	json.NewDecoder(r.Body).Decode(&deviceBlockJson)
	fmt.Printf("Set device block: %v\n", deviceBlockJson)

	setDeviceBlock(deviceBlockJson)
}

func getDeviceBlock(deviceId int) *DeviceBlock {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select db.device_id, db.from_time, db.to_time, db.block from device_block db where db.device_id = ? ", deviceId)
	checkError(err)
	defer rows.Close()

	var deviceBlock *DeviceBlock
	for rows.Next() {
		var deviceId int
		var fromTime string
		var toTime string
		var block int

		err = rows.Scan(&deviceId, &fromTime, &toTime, &block)
		checkError(err)
		deviceBlock = &DeviceBlock{DeviceId:deviceId, FromTime:fromTime, ToTime:toTime, Block:block}
		log.Printf("Device block: %v\n", deviceBlock)
	}
	err = rows.Err()
	checkError(err)

	return deviceBlock
}

func getDeviceBlockByMAC(deviceMAC string) *DeviceBlock {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	log.Printf("Get device by MAC: %s\n", deviceMAC)

	rows, err := db.Query("select db.device_id, db.from_time, db.to_time, db.block from device_block db inner join devices d on db.device_id = d.id where d.mac_addr = ? ", deviceMAC)
	checkError(err)
	defer rows.Close()

	var deviceBlock *DeviceBlock
	for rows.Next() {
		var deviceId int
		var fromTime string
		var toTime string
		var block int

		err = rows.Scan(&deviceId, &fromTime, &toTime, &block)
		checkError(err)
		deviceBlock = &DeviceBlock{DeviceId:deviceId, FromTime:fromTime, ToTime:toTime, Block:block}
		log.Printf("Device block: %v\n", deviceBlock)
	}
	err = rows.Err()
	checkError(err)

	return deviceBlock
}


func setDeviceBlock(deviceBlock DeviceBlock) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	log.Printf("Set device block for: %v\n", deviceBlock)

	stmt, err := db.Prepare("update device_block set from_time = ?, to_time = ? where device_id = ?")
	defer stmt.Close()
	checkError(err)

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(deviceBlock.FromTime, deviceBlock.ToTime, deviceBlock.DeviceId)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	loadAllBlockCrons()

	log.Printf("Set device block affected rows: %d\n", affected)
}

func loadAllBlockCrons() {
	if c != nil {
		c.Stop()
	}
	c = cron.New()
	c.Start()

	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select db.device_id, db.from_time, db.to_time, db.block from device_block db")
	checkError(err)
	defer rows.Close()

	var deviceBlock DeviceBlock
	for rows.Next() {
		var deviceId int
		var fromTime string
		var toTime string
		var block int

		err = rows.Scan(&deviceId, &fromTime, &toTime, &block)
		checkError(err)
		deviceBlock = DeviceBlock{DeviceId:deviceId, FromTime:fromTime, ToTime:toTime, Block:block}
		initDeviceBlockCron(deviceBlock)
		log.Printf("Device block cron initialized for: %v\n", deviceBlock)
	}

	err = rows.Err()
	checkError(err)

}

func initDeviceBlockCron(deviceBlock DeviceBlock) {
	fromSplit := strings.Split(deviceBlock.FromTime, ":")
	fromCron := fmt.Sprintf("0 %s %s * * *", fromSplit[1], fromSplit[0])
	log.Printf("From cron: %s\n", fromCron)
	c.AddFunc(fromCron, func() {
		log.Printf("Cron unblock for %d ran\n", deviceBlock.DeviceId)
		blockDevice(deviceBlock.DeviceId, 0)
	})
	toSplit := strings.Split(deviceBlock.ToTime, ":")
	toCron := fmt.Sprintf("0 %s %s * * *", toSplit[1], toSplit[0])
	log.Printf("To cron: %s\n", toCron)
	c.AddFunc(toCron, func() {
		log.Printf("Cron block for %d ran\n", deviceBlock.DeviceId)
		blockDevice(deviceBlock.DeviceId, 1)
	})
}

func addDeviceBlock(deviceId int) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	log.Printf("Add device block for: %d\n", deviceId)

	stmt, err := db.Prepare("insert into device_block values (?, ?, ?, ?)")
	checkError(err)
	defer stmt.Close()

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(deviceId, "00:00", "00:01", 1)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Add device block affected rows: %d\n", affected)
}



func blockDevice(deviceId int, block int) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	device := getDevice(deviceId)

	stmt, err := db.Prepare("update device_block set block = ? where device_id = ?")
	checkError(err)
	defer stmt.Close()

	tx, err := db.Begin()
	checkError(err)

	res, err := tx.Stmt(stmt).Exec(block, deviceId)
	checkError(err)

	affected, err := res.RowsAffected()
	checkError(err)

	tx.Commit()

	fmt.Printf("Device block affected rows: %d\n", affected)

	deviceMAC := device.MacAddr
	if block == 1 {
		executeBlockCmd(deviceMAC)
	} else {
		executeUnblockCmd(deviceMAC)
	}

}

func executeBlockCmd(deviceMAC string) {
	var cmd *exec.Cmd

	var out bytes.Buffer

	cmd = exec.Command("iptables", "-D", "FORWARD", "-i", "wlan0", "-o", "eth0", "-m", "mac", "--mac-source", deviceMAC, "-j", "ACCEPT")
	cmd.Stdout = &out
	err := cmd.Run()
	checkError(err)

	cmd = exec.Command("iptables", "-D", "FORWARD", "-i", "eth0", "-o", "wlan0", "-m", "mac", "--mac-source", deviceMAC, "-j", "ACCEPT")
	cmd.Stdout = &out
	err = cmd.Run()
	checkError(err)

	log.Printf("Device block command result: %s\n", out.String())
}

func executeUnblockCmd(deviceMAC string) {
	var cmd *exec.Cmd

	var out bytes.Buffer

	cmd = exec.Command("iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", "wlan0", "-o", "eth0", "-m", "mac", "--mac-source", deviceMAC, "-j", "ACCEPT")
	cmd.Stdout = &out
	err := cmd.Run()
	checkError(err)

	cmd = exec.Command("iptables", "-t", "filter", "-I", "FORWARD", "1", "-i", "eth0", "-o", "wlan0", "-m", "mac", "--mac-source", deviceMAC, "-j", "ACCEPT")
	cmd.Stdout = &out
	err = cmd.Run()
	checkError(err)

	log.Printf("Device unblock command result: %s\n", out.String())
}

func topDevicesHandler(w http.ResponseWriter, r *http.Request) {
	addr := strings.Join([]string{"127.0.0.1", strconv.Itoa(4711)}, ":")
	conn, err := net.Dial("tcp", addr)

	defer conn.Close()

	checkError(err)

	message := ">top-clients"
	conn.Write([]byte(message))
	log.Printf("Send: %s\n", message)

	timeoutDuration := 5 * time.Second
	bufReader := bufio.NewReader(conn)

	var line string

	var deviceQueryStatistics DeviceQueryStatistics

	for strings.Compare(line, "---EOM---") != 0 {
		conn.SetReadDeadline(time.Now().Add(timeoutDuration))

		buffer, err := bufReader.ReadBytes('\n')
		checkError(err)

		line = strings.TrimSpace(string(buffer))

		compare := strings.Compare(line, "---EOM---")
		fmt.Printf("Received: %s; Compare %d\n", line, compare)

		if compare != 0 {
			var position int
			var queries int
			var ip string
			var name string

			arr := strings.Split(line, " ")

			log.Printf("Line split: %s\n", arr)

			position, err = strconv.Atoi(arr[0])
			checkError(err)

			queries, err = strconv.Atoi(arr[1])
			checkError(err)

			ip = arr[2]
			if len(arr) > 3 {
				name = arr[3]
			} else {
				device := getDeviceByIP(ip)
				if device != nil {
					name = device.Name
				}
			}

			deviceQueryStatistic := DeviceQueryStatistic{Position: position, Queries: queries, Ip: ip, Name: name}
			log.Printf("Device statistic: %v\n", deviceQueryStatistic)

			deviceQueryStatistics = append(deviceQueryStatistics, deviceQueryStatistic)
		}
	}

	json.NewEncoder(w).Encode(deviceQueryStatistics)
	json.NewEncoder(os.Stdout).Encode(deviceQueryStatistics)
}

func topDomainsHandler(w http.ResponseWriter, r *http.Request) {
	addr := strings.Join([]string{"127.0.0.1", strconv.Itoa(4711)}, ":")
	conn, err := net.Dial("tcp", addr)

	defer conn.Close()

	checkError(err)

	message := ">top-domains"
	conn.Write([]byte(message))
	log.Printf("Send: %s\n", message)

	timeoutDuration := 5 * time.Second
	bufReader := bufio.NewReader(conn)

	var line string

	var domainQueryStatistics DomainQueryStatistics

	for strings.Compare(line, "---EOM---") != 0 {
		conn.SetReadDeadline(time.Now().Add(timeoutDuration))

		buffer, err := bufReader.ReadBytes('\n')
		checkError(err)

		line = strings.TrimSpace(string(buffer))

		compare := strings.Compare(line, "---EOM---")
		fmt.Printf("Received: %s; Compare %d\n", line, compare)

		if compare != 0 {
			var position int
			var queries int
			var name string

			arr := strings.Split(line, " ")

			log.Printf("Line split: %s\n", arr)

			position, err = strconv.Atoi(arr[0])
			checkError(err)

			queries, err = strconv.Atoi(arr[1])
			checkError(err)

			name = arr[2]

			domainQueryStatistic := DomainQueryStatistic{Position: position, Queries: queries, Name: name}
			log.Printf("Domain statistic: %v\n", domainQueryStatistic)

			domainQueryStatistics = append(domainQueryStatistics, domainQueryStatistic)
		}
	}

	json.NewEncoder(w).Encode(domainQueryStatistics)
	json.NewEncoder(os.Stdout).Encode(domainQueryStatistics)
}

func getDomainsForUserAgeBracket(deviceId int) []string {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select d.domain from domains d " +
		"inner join domain_age_bracket b on d.id = b.domain_id " +
		"inner join user_age_bracket uab on b.bracket_id = uab.bracket_id " +
		"inner join users u on uab.user_id = u.id " +
		"inner join user_device device on u.id = device.user_id " +
		"where device.device_id = ?", deviceId)
	checkError(err)
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string

		err = rows.Scan(&domain)
		checkError(err)
		log.Printf("Domain for user age bracket: %s\n", domain)

		domains = append(domains, domain)
	}
	err = rows.Err()
	checkError(err)

	return domains
}

func allQueriesClientHandler(w http.ResponseWriter, r *http.Request) {
	addr := strings.Join([]string{"127.0.0.1", strconv.Itoa(4711)}, ":")
	conn, err := net.Dial("tcp", addr)
	checkError(err)
	defer conn.Close()

	params := mux.Vars(r)
	log.Printf("All queries client params: %v\n", params)

	deviceId, err := strconv.Atoi(params["deviceId"])
	checkError(err)
	device := getDevice(deviceId)

	domains := getDomainsForUserAgeBracket(deviceId)

	message := fmt.Sprintf(">getallqueries-client %s", device.IpAddr)
	conn.Write([]byte(message))
	log.Printf("Send: %s\n", message)

	timeoutDuration := 5 * time.Second
	bufReader := bufio.NewReader(conn)

	var line string

	var domainQueryStatistics DomainQueryStatistics

	for strings.Compare(line, "---EOM---") != 0 {
		conn.SetReadDeadline(time.Now().Add(timeoutDuration))

		buffer, err := bufReader.ReadBytes('\n')
		checkError(err)

		line = strings.TrimSpace(string(buffer))

		compare := strings.Compare(line, "---EOM---")
		log.Printf("Received: %s; Compare %d\n", line, compare)

		if compare != 0 {
			var position int
			var queries int
			var name string

			arr := strings.Split(line, " ")

			position, err = strconv.Atoi(arr[0])
			checkError(err)

			queries, err = strconv.Atoi(arr[4])
			checkError(err)

			name = arr[2]

			add := false
			for i := range domains {
				if strings.Contains(name, domains[i]) {
					log.Printf("Found domain: %s\n", domains[i])
					add = true
				}
			}

			if add {
				domainQueryStatistic := DomainQueryStatistic{Position: position, Queries: queries, Name: name}
				log.Printf("All queries client: %v\n", domainQueryStatistic)
				domainQueryStatistics = append(domainQueryStatistics, domainQueryStatistic)
			}

		}
	}

	json.NewEncoder(w).Encode(domainQueryStatistics)
	json.NewEncoder(os.Stdout).Encode(domainQueryStatistics)
}


func rewardHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	var rewardJson UserReward
	json.NewDecoder(r.Body).Decode(&rewardJson)
	fmt.Printf("New reward: %v\n", rewardJson)

	deviceBlock := getDeviceBlockByMAC(rewardJson.DeviceMAC)
	log.Printf("Device block: %v\n", deviceBlock)

	if deviceBlock != nil {
		toTimeComponents := strings.Split(deviceBlock.ToTime, ":")

		hours, err := strconv.Atoi(toTimeComponents[0])
		checkError(err)

		minutes, err := strconv.Atoi(toTimeComponents[1])
		checkError(err)

		log.Printf("To time hours, minute: %d %d\n", hours, minutes)

		hours = hours + (int(minutes + rewardJson.RewardMinutes) / 60)
		minutes = (minutes + rewardJson.RewardMinutes) % 60

		log.Printf("New to time: %d:%d\n", hours, minutes)

		deviceBlock.ToTime = fmt.Sprintf("%02d:%02d", hours, minutes)
		log.Printf("New device block to time: %s\n", deviceBlock.ToTime)

		setDeviceBlock(*deviceBlock)

		log.Printf("Reward handled\n")
	}
}

func ageBracketsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "./clients.db")
	checkError(err)
	defer db.Close()

	rows, err := db.Query("select name from age_brackets")
	checkError(err)
	defer rows.Close()

	var ageBrackets[] string
	for rows.Next() {
		var ageBracket string

		err = rows.Scan(&ageBracket)
		checkError(err)
		ageBrackets = append(ageBrackets, ageBracket)
	}
	err = rows.Err()
	checkError(err)
	json.NewEncoder(w).Encode(ageBrackets)
	json.NewEncoder(os.Stdout).Encode(ageBrackets)
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
	Route{
		"CheckDeviceRegistration",
		"POST",
		"/check_device_registration",
		checkDeviceRegistration,
	},
	Route{
		"BlockDevice",
		"POST",
		"/devices/{deviceId}/{block}",
		deviceBlockHandler,
	},
	Route{
		"GetDeviceBlock",
		"GET",
		"/get_device_block/{deviceId}",
		getDeviceBlockHandler,
	},
	Route{
		"SetDeviceBlock",
		"POST",
		"/set_device_block",
		setDeviceBlockHandler,
	},
	Route{
		"TopDevices",
		"GET",
		"/top_devices",
		topDevicesHandler,
	},
	Route{
		"TopDomains",
		"GET",
		"/top_domains",
		topDomainsHandler,
	},
	Route{
		"Reward",
		"POST",
		"/reward",
		rewardHandler,
	},
	Route{
		"AgeBrackets",
		"GET",
		"/age_brackets",
		ageBracketsHandler,
	},
	Route{
		"AllQueriesClient",
		"GET",
		"/all_queries_client/{deviceId}",
		allQueriesClientHandler,
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
var c *cron.Cron

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

	loadAllBlockCrons()

	log.Printf("All cron jobs loaded\n")

	log.Fatal(http.ListenAndServe(":8080", router))
}
