					log.Println("modified file:", event.Name)
					return
				if !ok {
				if event.Op&fsnotify.Write == fsnotify.Write {
				log.Println("error:", err)
				log.Println("event:", event)
				return false
				return true
				}
			"${HOME}/config-${USER}.properties",
			"${HOME}/config.properties",
			"http://host/config",
			"http://host/config-${USER}",
			"traefik.frontend.rule.type":                 "PathPrefix",
			"traefik.ingress.kubernetes.io/ssl-redirect": "true",
			// ...
			// Both vals are equal so we should fall though
			// and let the key comparison take over.
			case err, ok := <-watcher.Errors:
			case event, ok := <-watcher.Events:
			conn, _ := ml.Accept()
			conn.Write([]byte("server error"))
			continue
			fmt.Printf("%s: %s\n", key, value)
			fmt.Println("Methods:", strings.Join(methods, ","))
			fmt.Println("Path regexp:", pathRegexp)
			fmt.Println("Queries regexps:", strings.Join(queriesRegexps, ","))
			fmt.Println("Queries templates:", strings.Join(queriesTemplates, ","))
			fmt.Println("ROUTE:", pathTemplate)
			go vh.Handle(conn)
			if i1.Val < i2.Val {
			log.Errorf("unable to read remote config: %v", err)
			return fmt.Errorf("not allowed")
			return true
			select {
			}
			} else if i1.Val > i2.Val {
		"annotations": map[string]interface{}{
		&Item{Key: "user:1", Val: "Jane"},
		&Item{Key: "user:2", Val: "Andy"},
		&Item{Key: "user:3", Val: "Steve"},
		&Item{Key: "user:4", Val: "Andrea"},
		&Item{Key: "user:5", Val: "Janet"},
		&Item{Key: "user:6", Val: "Andy"},
		- [Advanced use](#advanced-use)
		- [Certificate authority](#certificate-authority)
		- [DNS Challenge](#dns-challenge)
		- [Defaults](#defaults)
		- [Getting a tls.Config](#getting-a-tlsconfig)
		- [HTTP Challenge](#http-challenge)
		- [Providing an email address](#providing-an-email-address)
		- [Rate limiting](#rate-limiting)
		- [Serving HTTP handlers with HTTPS](#serving-http-handlers-with-https)
		- [Starting a TLS listener](#starting-a-tls-listener)
		- [TLS-ALPN Challenge](#tls-alpn-challenge)
		- [The `Config` type](#the-config-type)
		...
		// Config file not found; ignore error if desired
		// Config file was found but another error was produced
		// Here we use New to get a valid Config associated with the same cache.
		// The provided Config is used as a template and will be completed with
		// any defaults that are set in the Default config.
		// currently, only tested with etcd support
		// to implement a signal to notify the system of the changes
		// unmarshal new config into our runtime config struct. you can also use channel
		APIToken: "topsecret",
		Accept  []string      `properties:"accept,default=image/png;image;gif"`
		Enabled bool
		Host    string        `properties:"host"`
		ItemSize: v.GetInt("item-size"),
		MaxItems: v.GetInt("max-items"),
		Port    int           `properties:"port,default=9000"`
		Timeout time.Duration `properties:"timeout,default=5s"`
		Values map[string]interface{}
		acme.ChallengeTypeDNS01: solver,
		break
		conn.Close()
		conn.Write([]byte("bad request"))
		conn.Write([]byte("vhost not found"))
		delkeys = append(delkeys, k)
		err := runtime_viper.WatchRemoteConfig()
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		fmt.Printf("%s: %s\n", key, value)
		fmt.Printf("key: %s, value: %s\n", key, value)
		fmt.Println("Is Cygwin/MSYS2 Terminal")
		fmt.Println("Is Not Terminal")
		fmt.Println("Is Terminal")
		fmt.Println("Order by age range 30-50")
		fmt.Println("Order by age")
		fmt.Println("Order by last name")
		fmt.Println("We have Streaming SIMD 2 Extensions")
		fmt.Println()
		fmt.Println(err)
		fn(flag)
		for {
		if conn != nil {
		if err != nil {
		if err == nil {
		if name != "example.com" {
		if tag == "vals" {
		keys.ReplaceOrInsert(user)
		kvi := item.(*Item)
		log.Fatal(err)
		log.Fatalf("unable to marshal config to YAML: %v", err)
		log.Printf("closed conn: %s", err)
		log.Printf("got a bad request!")
		log.Printf("got a connection for an unknown vhost")
		methods, err := route.GetMethods()
		moduleConfig `mapstructure:",squash"`
		name = "new-flag-name"
		name = strings.Replace(name, sep, to, -1)
		pathRegexp, err := route.GetPathRegexp()
		pathTemplate, err := route.GetPathTemplate()
		queriesRegexps, err := route.GetQueriesRegexp()
		queriesTemplates, err := route.GetQueriesTemplates()
		return // challenge handled; nothing else to do
		return certmagic.New(cache, certmagic.Config{
		return err
		return net.Dial("unix", unixSocket)
		return nil
		return true
		runtime_viper.Unmarshal(&runtime_conf)
		t.Errorf("file \"%s\" does not exist.\n", name)
		time.Sleep(time.Second * 5) // delay after each request
		tx.Ascend("age", func(key, value string) bool {
		tx.Ascend("last_name", func(key, value string) bool {
		tx.AscendRange("age", `{"age":30}`, `{"age":50}`, func(key, value string) bool {
		tx.Set("1", `{"name":{"first":"Tom","last":"Johnson"},"age":38}`, nil)
		tx.Set("2", `{"name":{"first":"Janet","last":"Prichard"},"age":47}`, nil)
		tx.Set("3", `{"name":{"first":"Carol","last":"Anderson"},"age":52}`, nil)
		tx.Set("4", `{"name":{"first":"Alan","last":"Cooper"},"age":28}`, nil)
		vals.ReplaceOrInsert(user)
		}
		})
		}), nil
		},
		}, properties.UTF8, true)
		}, true)
	
	"flag"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"github.com/klauspost/cpuid/v2"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/magiconair/properties"
	"github.com/mattn/go-isatty"
	"github.com/spf13/pflag"
	"github.com/subosito/gotenv"
	"github.com/tidwall/btree"
	"github.com/tidwall/buntdb"
	"ingress": map[string]interface{}{
	"log"
	"net/http"
	"os"
	"strings"
	- (This is a requirement of the ACME protocol, not a library limitation)
	- Active locking
	- Caddy / CertMagic pioneered this technology
	- Challenges are randomized to avoid accidental dependence
	- Challenges are rotated to overcome certain network blockages
	- Custom decision functions to regulate and throttle on-demand behavior
	- Exponential backoff with carefully-tuned intervals
	- Highly efficient, coordinated management in a fleet
	- Or they can be forwarded to other ports you control
	- Or use the DNS challenge to waive this requirement
	- Other integrations available/possible
	- RFC 8737 (tls-alpn-01 challenge)
	- Retries with optional test/staging CA endpoint instead of production, to avoid rate limits
	- Robust retries for up to 30 days
	- Smart queueing
	- Staples stored to disk in case of responder outages
	- Typically the local file system (default)
	- Will [automatically attempt](https://twitter.com/mholt6/status/1235577699541762048) to replace [revoked certificates](https://community.letsencrypt.org/t/2020-02-29-caa-rechecking-bug/114591/3?u=mholt)!
	- [Behind a load balancer (or in a cluster)](#behind-a-load-balancer-or-in-a-cluster)
	- [Cache](#cache)
	- [Development and testing](#development-and-testing)
	- [Device attestation challenges](https://datatracker.ietf.org/doc/draft-acme-device-attest/)
	- [Examples](#examples)
	- [On-Demand TLS](#on-demand-tls)
	- [Package Overview](#package-overview)
	- [Storage](#storage)
	- [The ACME Challenges](#the-acme-challenges)
	- [Wildcard Certificates](#wildcard-certificates)
	- `certificate_path`: The path to the public key file in storage
	- `certificate`: The Certificate struct
	- `client_hello`: The tls.ClientHelloInfo struct
	- `error`: The (final) error message
	- `forced`: Whether renewal is being forced (if renewal)
	- `identifier`: The name on the certificate
	- `issuer`: The previous or current issuer
	- `issuers`: The issuer(s) tried
	- `metadata_path`: The path to the metadata file in storage
	- `private_key_path`: The path to the private key file in storage
	- `reason`: The OCSP revocation reason
	- `remaining`: Time left on the certificate (if renewal)
	- `renewal`: Whether this is a renewal
	- `revoked_at`: When the certificate was revoked
	- `sans`: The subject names on the certificate
	- `storage_path`: The path to the folder containing the cert resources within storage
	- `subjects`: The subject names on the certificate
	. "github.com/klauspost/cpuid/v2"
	...
	// ...
	// Create a tree for keys and a tree for values.
	// Create some items.
	// Default is 80
	// Default is an empty string
	// Default is false
	// Default is two spaces
	// Indent is the nested indentation
	// Insert each user into both trees
	// Iterate over each user in the key tree
	// Iterate over each user in the val tree
	// Need to create a router that we can pass the request through so that the vars will be added to the context
	// Open the data.db file. It will be created if it doesn't exist.
	// Output:
	// Prefix is a prefix for all lines
	// Print basic CPU information:
	// SortKeys will sort the keys alphabetically
	// Test if we have these specific features:
	// The "keys" tree will be sorted on the Keys field.
	// The "values" tree will be sorted on the Values field.
	// Width is an max column width for single line arrays
	// [100 0] [101 1]
	// any customizations you need go here
	// create test files and directories
	// get values through getters
	// init from a file
	// not a map
	// or from a URL
	// or from a map
	// or from a string
	// or from flags
	// or from multiple URLs
	// or multiple files
	// or through Decode
	// plus any other customizations you need
	// using standard library "flag" package
	// vhost.Name is a virtual hostname like "foo.example.com"
	<-done
	<a href="https://github.com/caddyserver/certmagic/actions?query=workflow%3ATests"><img src="https://github.com/caddyserver/certmagic/workflows/Tests/badge.svg"></a>
	<a href="https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
	<a href="https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc"><img src="https://user-images.githubusercontent.com/1128849/49704830-49d37200-fbd5-11e8-8385-767e0cd033c3.png" alt="CertMagic" width="550"></a>
	<a href="https://sourcegraph.com/github.com/caddyserver/certmagic?badge"><img src="https://sourcegraph.com/github.com/caddyserver/certmagic/-/badge.svg"></a>
	Agreed: true,
	CA:     certmagic.LetsEncryptStagingCA,
	ChallengeSolvers: map[string]acmez.Solver{
	Chart struct{
	DNSProvider: &cloudflare.Provider{
	DNSProvider: &cloudflare.Provider{APIToken: "topsecret"},
	DecisionFunc: func(name string) error {
	Dial: func(_, _ string) (net.Conn, error) {
	Email:  "you@yours.com",
	GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
	ID: "foobar",
	Indent string
	Key, Val string
	Module struct {
	Name string
	Name:  "sub",
	PathMap string `mapstructure:"path_map"`
	Port int
	Prefix string
	SortKeys bool
	Token string
	Type:  "A",
	Value: "1.2.3.4",
	Width int
	_, _, err := tx.Set("mykey", "myvalue", nil)
	_, err := appFS.Stat(name)
	afero.WriteFile(appFS, "src/a/b", []byte("file b"), 0644)
	afero.WriteFile(appFS, "src/c", []byte("file c"), 0644)
	amw.tokenUsers["00000000"] = "user0"
	amw.tokenUsers["05f717e5"] = "randomUser"
	amw.tokenUsers["aaaaaaaa"] = "userA"
	amw.tokenUsers["deadbeef"] = "user0"
	appFS := afero.NewMemMapFs()
	appFS.MkdirAll("src/a", 0755)
	base := afero.NewOsFs()
	bs, err := yaml.Marshal(c)
	c := viper.AllSettings()
	case "old-flag-name":
	case string:
	case vhost.BadRequest:
	case vhost.Closed:
	case vhost.NotFound:
	color.NoColor = true // disables colorized output
	conn, err := mux.NextError()
	cpuid.Detect()
	cpuid.Flags()
	db, _ := buntdb.Open(":memory:")
	db, err := buntdb.Open("data.db")
	db.CreateIndex("age", "*", buntdb.IndexJSON("age"))
	db.CreateIndex("last_name", "*", buntdb.IndexJSON("name.last"))
	db.Update(func(tx *buntdb.Tx) error {
	db.View(func(tx *buntdb.Tx) error {
	default:
	defer db.Close()
	defer watcher.Close()
	done := make(chan bool)
	err := r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
	err := tx.Ascend("", func(key, value string) bool {
	err = watcher.Add("/tmp/foo")
	fh, _ = ufs.Create("/home/test/file2.txt")
	fh.Close()
	fh.WriteString("This is a test")
	flag "github.com/spf13/pflag"
	flag.BoolVarP(&flagvar, "boolname", "b", true, "help message")
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Int("flagname", 1234, "help message for flagname")
	flag.Parse()
	flags []myFlag
	flags: []myFlag{myFlag{}, myFlag{}},
	fmt.Fprintf(w, "Lookit my cool website over HTTPS!")
	fmt.Printf("%v %v\n", r.Min, r.Max)
	fmt.Printf("\n")
	fmt.Printf("value is %s\n", val)
	fmt.Printf(buf, "%s %s\n", key, val)
	fmt.Println("Cacheline bytes:", CPU.CacheLine)
	fmt.Println("Config file changed:", e.Name)
	fmt.Println("Family", CPU.Family, "Model:", CPU.Model, "Vendor ID:", CPU.VendorID)
	fmt.Println("Features:", strings.Join(CPU.FeatureSet(), ","))
	fmt.Println("Frequency", CPU.Hz, "hz")
	fmt.Println("L1 Data Cache:", CPU.Cache.L1D, "bytes")
	fmt.Println("L1 Instruction Cache:", CPU.Cache.L1I, "bytes")
	fmt.Println("L2 Cache:", CPU.Cache.L2, "bytes")
	fmt.Println("L3 Cache:", CPU.Cache.L3, "bytes")
	fmt.Println("LogicalCores:", CPU.LogicalCores)
	fmt.Println("Name:", CPU.BrandName)
	fmt.Println("PhysicalCores:", CPU.PhysicalCores)
	fmt.Println("ThreadsPerCore:", CPU.ThreadsPerCore)
	fmt.Println("verbose enabled")
	for _, flag := range flags {
	for _, sep := range from {
	for _, user := range users {
	for {
	from := []string{"-", "_"}
	go func() {
	go func(vh virtualHost, ml net.Listener) {
	goflag "flag"
	gotenv.Load()
	host := p.MustGetString("host")
	http.Handle("/", r)
	i := viper.GetInt("flagname") // retrieve value from viper
	i2 := item.(*Item)
	if CPU.Supports(SSE, SSE2) {
	if _, err = tx.Delete(k); err != nil {
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
	if conn != nil {
	if cpuid.CPU.Supports(cpuid.SSE, cpuid.SSE2) {
	if err != nil {
	if err != nil{
	if err := p.Decode(&cfg); err != nil {
	if isatty.IsTerminal(os.Stdout.Fd()) {
	if myACME.HandleHTTPChallenge(w, r) {
	if os.IsNotExist(err) {
	if someCondition(k) == true {
	keys := btree.New(16, "keys")
	keys.Ascend(func(item btree.Item) bool {
	log.Fatal(err)
	log.Println(os.Getenv("APP_ID"))     // "1234567"
	log.Println(os.Getenv("APP_SECRET")) // "abcdef"
	muxListener, _ := mux.Listen(vhost.Name())
	name := "src/c"
	p := properties.MustLoadFile("${HOME}/config.properties", properties.UTF8)
	p = properties.LoadMap(map[string]string{"key": "value", "abc": "def"})
	p = properties.MustLoadFiles([]string{
	p = properties.MustLoadString("key=value\nabc=def")
	p = properties.MustLoadURL("http://host/path")
	p = properties.MustLoadURL([]string{
	p.MustFlag(flag.CommandLine)
	panic("Not a valid TLS connection!")
	panic("Not a valid http connection!")
	panic("cache configuration not found")
	panic(fmt.Errorf("Fatal error config file: %w \n", err))
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	port := p.GetInt("port", 8080)
	println("has a last name")
	println("no last name")
	println(name.String())
	println(val)
	println(value.String())
	println(value.String()) 
	r := grect.Get(`{
	r := mux.NewRouter()
	r.HandleFunc("/", handler)
	r.HandleFunc("/articles", handler).Methods("GET")
	r.HandleFunc("/articles/{id}", handler).Methods("GET", "PUT")
	r.HandleFunc("/authors", handler).Queries("surname", "{surname}")
	r.HandleFunc("/products", handler).Methods("POST")
	return
	return &Cache{
	return err
	return errors.New("invalid json")
	return i1.Key < i2.Key
	return nil
	return pflag.NormalizedName(name)
	return string(bs)
	return true
	return true // continue
	return true // keep iterating
	roBase := afero.NewReadOnlyFs(base)
	router := mux.NewRouter()
	switch err.(type) {
	switch name {
	switch tag := ctx.(type) {
	t.Fatalf("unable to decode into struct, %v", err)
	to := "."
	tokenUsers map[string]string
	tx.Ascend("ages", func(key, val string) bool {
	tx.Ascend("last_name_age", func(key, value string) bool {
	tx.Ascend("names", func(key, val string) bool {
	tx.Intersects("fleet", "[-117 30],[-112 36]", func(key, val string) bool {
	tx.Nearby("fleet", "[-113 33]", func(key, val string, dist float64) bool {
	tx.Set("1", `{"name":{"first":"Tom","last":"Johnson"},"age":38}`, nil)
	tx.Set("2", `{"name":{"first":"Janet","last":"Prichard"},"age":47}`, nil)
	tx.Set("3", `{"name":{"first":"Carol","last":"Anderson"},"age":52}`, nil)
	tx.Set("4", `{"name":{"first":"Alan","last":"Cooper"},"age":28}`, nil)
	tx.Set("5", `{"name":{"first":"Sam","last":"Anderson"},"age":51}`, nil)
	tx.Set("6", `{"name":{"first":"Melinda","last":"Prichard"},"age":44}`, nil)
	tx.Set("fleet:0:pos", "[-115.567 33.532]", nil)
	tx.Set("fleet:1:pos", "[-116.671 35.735]", nil)
	tx.Set("fleet:2:pos", "[-113.902 31.234]", nil)
	tx.Set("mykey", "myval", &buntdb.SetOptions{Expires:true, TTL:time.Second})
	tx.Set("user:0:age", "35", nil)
	tx.Set("user:0:name", "tom", nil)
	tx.Set("user:1:age", "49", nil)
	tx.Set("user:1:name", "Randi", nil)
	tx.Set("user:2:age", "13", nil)
	tx.Set("user:2:name", "jane", nil)
	tx.Set("user:4:age", "63", nil)
	tx.Set("user:4:name", "Janet", nil)
	tx.Set("user:5:age", "8", nil)
	tx.Set("user:5:name", "Paula", nil)
	tx.Set("user:6:age", "3", nil)
	tx.Set("user:6:name", "peter", nil)
	tx.Set("user:7:age", "16", nil)
	tx.Set("user:7:name", "Terri", nil)
	type Config struct {
	ufs := afero.NewCopyOnWriteFs(roBase, afero.NewMemMapFs())
	users := []*Item{
	val, err := tx.Get("mykey")
	vals := btree.New(16, "vals")
	vals.Ascend(func(item btree.Item) bool {
	value := gjson.Get(json, "name.last")
	var cfg Config
	var eight interface{} = 8
	var foo interface{} = "one more time"
	vhost := v
	viper.BindPFlags(pflag.CommandLine)
	watcher, err := fsnotify.NewWatcher()
	yaml "gopkg.in/yaml.v2"
	}
	} else if isatty.IsCygwinTerminal(os.Stdout.Fd()) {
	} else {
	}()
	}(vhost, muxListener)
	})
	},

 
    
        	// Pass down the request to the next middleware (or final handler)
        	// We found the token in our map
        	// Write an error and stop the handler chain
        	http.Error(w, "Forbidden", http.StatusForbidden)
        	log.Printf("Authenticated user %s\n", user)
        	next.ServeHTTP(w, r)
                                 "category", "technology",
                                 "filter", "gorilla")
                                 "id", "42")
                                 "id", "42",
                        resty.DomainCheckRedirectPolicy("host1.com", "host2.org", "host3.net"))
                    "Don't waste your time!")
                    goproxy.ContentTypeText,http.StatusForbidden,
                D        []int `yaml:",flow"`
                RenamedC int   `yaml:"c"`
                log.Fatalf("error: %v", err)
                tc.routeVariable, rr.Code, http.StatusOK)
            "host": "127.0.0.1",
            "host": "198.0.0.1",
            "port": 2112
            "port": 3099
            5799,
            6029
            log.Println(err)
            return r,goproxy.NewResponse(r,
            rr.Body.String(), expected)
            status, http.StatusOK)
            t.Errorf("handler should have failed on routeVariable %s: got %v want %v",
            t.Fatal(err)
          "description": "the AMI to use"
          "first_name": "Jeevanandam",
          "last_name": "M",
          "limit": "20",
          "order": "asc",
          "page_no": "1",
          "random":strconv.FormatInt(time.Now().Unix(), 10),
          "sort":"name",
          Get("http://bit.ly/1LouEKr")
          SetOutput("/MyDownloads/plugin/ReplyWithHeader-v5.1-beta.zip").
          SetOutput("plugin/ReplyWithHeader-v5.1-beta.zip").
          [100.0, 1.0], [100.0, 0.0] ]
        "Content-Type": "application/json",
        "User-Agent": "My custom User Agent String",
        "access_token": "C6A79608-782F-4ED0-A11D-BD82FAD829CD",
        "address": "localhost",
        "city": "my city",
        "city": "new city update",
        "first_name": "Jeevanandam",
        "fmt"
        "gopkg.in/yaml.v2"
        "last_name": "M",
        "log"
        "metric": {
        "notes": "/Users/jeeva/text-file.txt",
        "password": "mypass",
        "port": 5799
        "ports": [
        "profile_img": "/Users/jeeva/test-img.png",
        "username": "jeeva",
        "warehouse": {
        "zip_code": "00001",
        - Error scenario [Request.SetError()](https://pkg.go.dev/github.com/go-resty/resty/v2#Request.SetError) and [Response.Error()](https://pkg.go.dev/github.com/go-resty/resty/v2#Response.Error).
        - Success scenario [Request.SetResult()](https://pkg.go.dev/github.com/go-resty/resty/v2#Request.SetResult) and [Response.Result()](https://pkg.go.dev/github.com/go-resty/resty/v2#Response.Result).
        - Supports [RFC7807](https://tools.ietf.org/html/rfc7807) - `application/problem+json` & `application/problem+xml`
        // Call the next handler, which can be another middleware in the chain, or the final handler.
        // Do stuff here
        // Good practice to set timeouts to avoid Slowloris attacks.
        // Good practice: enforce timeouts for servers you create!
        // In this case, our MetricsHandler returns a non-200 response
        // Including "err != nil" emulates the default retry behavior for errors encountered during the request.
        // This is a pretty serious error and the user should know about
        // default thresholds.
        // expects. Under the default thresholds, Warn will be logged, but
        // for a route variable it doesn't know about.
        // it. It will be printed to the terminal as well as logged under the
        // not printed to the terminal. 
        A string
        Addr:         "0.0.0.0:8080",
        Addr:         "127.0.0.1:8000",
        Author: "Jeevanandam M",
        B struct {
        Content: "This is my article content, oh ya!",
        Handler:      r,
        Handler: r, // Pass our instance of gorilla/mux in.
        IdleTimeout:  time.Second * 60,
        ReadTimeout:  15 * time.Second,
        ReadTimeout:  time.Second * 15,
        Tags: []string{"article", "sample", "resty"},
        Tags: []string{"new tag1", "new tag2"},
        Title: "go-resty",
        WriteTimeout: 15 * time.Second,
        WriteTimeout: time.Second * 15,
        [ [100.0, 0.0], [101.0, 0.0], [101.0, 1.0],
        ]
        d, err := yaml.Marshal(&t)
        d, err = yaml.Marshal(&m)
        err := yaml.Unmarshal([]byte(data), &t)
        err = yaml.Unmarshal([]byte(data), &m)
        fmt.Printf("--- m dump:\n%s\n\n", string(d))
        fmt.Printf("--- m:\n%v\n\n", m)
        fmt.Printf("--- t dump:\n%s\n\n", string(d))
        fmt.Printf("--- t:\n%v\n\n", t)
        if err != nil {
        if err := srv.ListenAndServe(); err != nil {
        if h,_,_ := time.Now().Clock(); h >= 8 && h <= 17 {
        if rr.Code == http.StatusOK && !tc.shouldPass {
        if user, found := amw.tokenUsers[token]; found {
        jww "github.com/spf13/jwalterweatherman"
        jww.ERROR.Println(err)
        jww.SetLogThreshold(jww.LevelTrace)
        jww.SetStdoutThreshold(jww.LevelInfo)
        jww.WARN.Println(err2)
        key = "value"
        log.Println(r.RequestURI)
        m := make(map[interface{}]interface{})
        next.ServeHTTP(w, r)
        path := fmt.Sprintf("/metrics/%s", tc.routeVariable)
        r.Header.Set("X-GoProxy","yxorPoG-X")
        req, err := http.NewRequest("GET", path, nil)
        return
        return 0, errors.New("quota exceeded")
        return err != nil || r.StatusCode() == http.StatusTooManyRequests
        return r,nil
        return r.StatusCode() == http.StatusTooManyRequests
        routeVariable string
        router.HandleFunc("/metrics/{type}", MetricsHandler)
        router.ServeHTTP(rr, req)
        rr := httptest.NewRecorder()
        shouldPass bool
        t := T{}
        t.Errorf("handler returned unexpected body: got %v want %v",
        t.Errorf("handler returned wrong status code: got %v want %v",
        t.Fatal(err)
        token := r.Header.Get("X-Session-Token")
        {"adhadaeqm3k", false},
        {"counters", true},
        {"goroutines", true},
        {"heap", true},
        {"queries", true},
        }
        } else {
        },
      "Accept-Encoding": "gzip",
      "Host": "httpbin.org",
      "User-Agent": "go-resty/2.4.0 (https://github.com/go-resty/resty)",
      "X-Amzn-Trace-Id": "Root=1-5f5ff031-000ff6292204aa6898e4de49"
      "age": 44
      "alignment": "center"
      "alignment": "center",
      "ami": {
      "api_key": "api-key-here",
      "api_secret": "api-secret",
      "coordinates": [
      "data": "Click Here",
      "first": "Janet",
      "firstName": "Elliotte", 
      "firstName": "Janet", 
      "firstName": "Jason", 
      "hOffset": 250,
      "height": 500
      "last": "Murphy",
      "lastName": "Harold", 
      "lastName": "Hunter", 
      "lastName": "McLaughlin", 
      "name": "main_window",
      "onMouseUp": "sun1.opacity = (sun1.opacity / 100) * 90;"
      "size": 36,
      "src": "Images/Sun.png",
      "style": "bold",
      "title": "Sample Konfabulator Widget",
      "type": "Polygon",
      "vOffset": 100,
      "vOffset": 250,
      "width": 500,
      * Since v2.4.0, trace info contains a `RequestAttempt` value, and the `Request` object contains an `Attempt` attribute
      --coolflag string   it's really cool flag (default "yeaah")
      --usefulflag int    sometimes it's very useful (default 777)
      Delete("https://myapp.com/articles")
      Delete("https://myapp.com/articles/1234")
      Domain: "sample.com",
      ForceContentType("application/json").
      Get("/search_result")
      Get("/show_product")
      Get("v2/alpine/manifests/latest")
      Head("https://myapp.com/videos/hi-res-video")
      HttpOnly: true,
      MaxAge: 36000,
      Name:"go-resty",
      Options("https://myapp.com/servers/nyc-dc-01")
      Patch("https://myapp.com/articles/1234")
      Path: "/",
      Post("http://myapp.com/login")
      Post("http://myapp.com/profile")
      Post("http://myapp.com/search")
      Post("http://myapp.com/upload")
      Post("https://content.dropboxapi.com/1/files_put/auto/resty/mydocument.pdf") // for upload Dropbox supports PUT too
      Post("https://myapp.com/login")
      Put("https://myapp.com/article/1234")
      Secure: false,
      SetAuthToken("<your-auth-token>").
      SetAuthToken("BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F").
      SetAuthToken("C6A79608-782F-4ED0-A11D-BD82FAD829CD").
      SetBody(Article{
      SetBody(User{Username: "testuser", Password: "testpass"}).
      SetBody([]byte(`{"username":"testuser", "password":"testpass"}`)).
      SetBody(`{"username":"testuser", "password":"testpass"}`).
      SetBody(`{article_ids: [1002, 1006, 1007, 87683, 45432] }`).
      SetBody(fileBytes).
      SetBody(map[string]interface{}{"username": "testuser", "password": "testpass"}).
      SetContentLength(true).          // Dropbox expects this value
      SetError(&AuthError{}).       // or SetError(AuthError{}).
      SetError(&DropboxError{}).       // or SetError(DropboxError{}).
      SetError(&Error{}).       // or SetError(Error{}).
      SetFile("profile_img", "/Users/jeeva/test-img.png").
      SetFileReader("notes", "text-file.txt", bytes.NewReader(notesBytes)).
      SetFileReader("profile_img", "test-img.png", bytes.NewReader(profileImgBytes)).
      SetFiles(map[string]string{
      SetFormData(map[string]string{
      SetFormDataFromValues(criteria).
      SetHeader("Accept", "application/json").
      SetHeader("Content-Type", "application/json").
      SetQueryParams(map[string]string{
      SetQueryString("productId=232&template=fresh-sample&cat=resty&source=google&kw=buy a lot more").
      SetResult(&AuthSuccess{}).    // or SetResult(AuthSuccess{}).
      SetResult(result).
      Value:"This is cookie value",
      allowing you to deal in `error` values exclusively.
      like appending into the same error object from a loop.
      })
      }).
    "ADX",
    "AESNI",
    "AVX",
    "AVX2",
    "Available": false,
    "BMI1",
    "BMI2",
    "CLMUL",
    "CLZERO",
    "CMOV",
    "CMPXCHG8",
    "CPBOOST",
    "CX16",
    "EPCSections": null
    "F16C",
    "FMA3",
    "FXSR",
    "FXSROPT",
    "HTT",
    "HYPERVISOR",
    "L1D": 32768,
    "L1I": 32768,
    "L2": 524288,
    "L3": 16777216
    "LAHF",
    "LZCNT",
    "LaunchControl": false,
    "MCAOVERFLOW",
    "MMX",
    "MMXEXT",
    "MOVBE",
    "MaxEnclaveSize64": 0,
    "MaxEnclaveSizeNot64": 0,
    "NX",
    "OSXSAVE",
    "POPCNT",
    "RDRAND",
    "RDSEED",
    "RDTSCP",
    "SCE",
    "SGX1Supported": false,
    "SGX2Supported": false,
    "SHA",
    "SSE",
    "SSE2",
    "SSE3",
    "SSE4",
    "SSE42",
    "SSE4A",
    "SSSE3",
    "SUCCOR",
    "X87",
    "XSAVE"
    "access_token": "BC594900-518B-4F7E-AC75-BD37F019E08F",
    "args": {},
    "context"
    "datastore": {
    "datastore.metric.host": "0.0.0.0",
    "debug": "on",
    "first": "Tom",
    "flag"
    "github.com/elazarl/goproxy"
    "github.com/gorilla/mux"
    "headers": {
    "host": {
    "hostname": "myhostname.com"
    "image": { 
    "last": "Anderson"
    "log"
    "net/http"
    "net/http/httptest"
    "origin": "0.0.0.0",
    "os"
    "os/signal"
    "port": 8080,
    "testing"
    "text": {
    "time"
    "url": "https://httpbin.org/get"
    "window": {
    $ go get github.com/spf13/afero
    )
    * Access as `[]byte` array - `response.Body()` OR Access as `string` - `response.String()`
    * Auto detects `Content-Type`
    * Auto detects file content type
    * Backoff Retry
    * Buffer less processing for `io.Reader`
    * Conditional Retry
    * Create Multiple clients if you want to `resty.New()`
    * Debug mode - clean and informative logging presentation
    * Default is `JSON`, if you supply `struct/map` without header `Content-Type`
    * DomainCheckRedirectPolicy
    * FlexibleRedirectPolicy
    * For auto-unmarshal, refer to -
    * Gzip - Go does it automatically also resty has fallback handling too
    * Have client level settings & options and also override at Request level if you want to
    * Know your `response.Time()` and when we `response.ReceivedAt()`
    * Native `*http.Request` instance may be accessed during middleware and request execution via `Request.RawRequest`
    * NoRedirectPolicy
    * Request Body can be read multiple times via `Request.RawRequest.GetBody()`
    * Request and Response middleware
    * Resty Client trace, see [Client.EnableTrace](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.EnableTrace) and [Request.EnableTrace](https://pkg.go.dev/github.com/go-resty/resty/v2#Request.EnableTrace)
    * Resty provides an option to override [JSON Marshal/Unmarshal and XML Marshal/Unmarshal](#override-json--xml-marshalunmarshal)
    * Since v2.6.0, Retry Hooks - [Client](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.AddRetryHook), [Request](https://pkg.go.dev/github.com/go-resty/resty/v2#Request.AddRetryHook)
    * Supports `http.RoundTripper` implementation, see [SetTransport](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.SetTransport)
    * Works fine with `HTTP/2` and `HTTP/1.1`
    * etc. [more info](redirect.go)
    * goroutine concurrent safe
    - It avoids allocations where possible.
    - It keeps the underlying error type hidden,
    - It provides APIs to safely append into an error from a `defer` statement.
    - It utilizes slice resizing semantics to optimize common cases
    - The `errors.Is` and `errors.As` functions *just work*.
    ...
    // (e.g. Redis) by performing a simple PING, and include them in the response.
    // <-ctx.Done() if your application should wait for other services
    // A route with a route variable:
    // A very simple health check.
    // Add your routes as needed
    // Bind to a port and pass our router in
    // Block until we receive our signal.
    // Check the response body is what we expect.
    // Check the status code is what we expect.
    // Create a deadline to wait for.
    // Create a request to pass to our handler. We don't have any query parameters for now, so we'll
    // Default (nil) implies exponential backoff with jitter
    // Default is 100 milliseconds.
    // Default is 2 seconds.
    // Doesn't block if no connections, but will otherwise wait
    // IMPORTANT: you must specify an OPTIONS method matcher for the middleware to set CORS headers
    // In the future we could report back on the status of our DB, or our cache
    // MaxWaitTime can be overridden as well.
    // Now you have access to Client and current Request object
    // Now you have access to Client and current Response object
    // Optionally, you could run srv.Shutdown in a goroutine and block on
    // Our handlers satisfy http.Handler, so we can call their ServeHTTP method
    // RetryConditionFunc type is for retry condition function
    // Routes consist of a path and a handler function.
    // Run our server in a goroutine so that it doesn't block.
    // SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
    // Set retry count to non zero to enable retries
    // SetRetryAfter sets callback to calculate wait time between retries.
    // This will serve files under http://localhost:8000/static/<filename>
    // We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
    // We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
    // You can override initial retry wait time.
    // directly and pass in our Request and ResponseRecorder.
    // discarded.
    // important for the user. Under the default thresholds this will be
    // input: non-nil Response OR request execution error
    // manipulate it as per your need
    // pass 'nil' as the third parameter.
    // to finalize based on context cancellation.
    // until the timeout deadline.
    // v.Err contains the original error
    // v.Response contains the last response from the server
    <-c
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
    Any text may be used in place of `EOF`. Example:
    EnableTrace().
    Example: `"Hello, World"`
    Get("https://httpbin.org/get")
    Password string
    Postgres Postgres
    SetJSONMarshaler(json.Marshal).
    SetJSONUnmarshaler(json.Unmarshal)
    SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
    SetRetryCount(3).
    SetRetryMaxWaitTime(20 * time.Second).
    SetRetryWaitTime(5 * time.Second).
    SetXMLUnmarshaler(xml.Unmarshal)
    User     string
    `["foo", "bar", 42]`. Arrays can contain primitives,
    ```
    ```hcl
    and syntax that HCL was based off of.
    are not allowed. A multi-line comment (also known as a block comment)
    c := make(chan os.Signal, 1)
    cast.ToInt("8")                // 8
    cast.ToInt(8)                  // 8
    cast.ToInt(8.31)               // 8
    cast.ToInt(eight)              // 8
    cast.ToInt(false)              // 0
    cast.ToInt(nil)                // 0
    cast.ToInt(true)               // 1
    cast.ToString("mayonegg")         // "mayonegg"
    cast.ToString(8)                  // "8"
    cast.ToString(8.31)               // "8.31"
    cast.ToString([]byte("one time")) // "one time"
    cast.ToString(foo)                // "one more time"
    cast.ToString(nil)                // ""
    ctx, cancel := context.WithTimeout(context.Background(), wait)
    defer cancel()
    description = "the AMI to use"
    enabled: true
    expected := `{"alive": true}`
    flag.DurationVar(&wait, "graceful-timeout", time.Second * 15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
    flag.IntVar(&flagvar, "flagname", 1234, "help message for flagname")
    flag.Parse()
    flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
    fmt.Fprintf(w, "Category: %v\n", vars["category"])
    fmt.Printf("Query result %d: %v\n", ii, item)
    for _, tc := range tt {
    func(r *http.Request,ctx *goproxy.ProxyCtx)(*http.Request,*http.Response) {
    func(r *resty.Response, err error) bool {
    go build github.com/miekg/dns
    go func() {
    go get github.com/miekg/dns
    go get github.com/spf13/pflag
    go get gopkg.in/yaml.v2
    go install github.com/pelletier/go-toml/cmd/jsontoml
    go install github.com/pelletier/go-toml/cmd/tomljson
    go install github.com/pelletier/go-toml/cmd/tomll
    go test github.com/spf13/pflag
    handler := http.HandlerFunc(HealthCheckHandler)
    handler.ServeHTTP(rr, req)
    http.Handle("/", r)
    http.ListenAndServe(":8080", r)
    https://github.com/k-takata/go-iscygpty
    if Verbose {
    if err != nil {
    if err2 != nil {
    if r.Method == http.MethodOptions {
    if rr.Body.String() != expected {
    if status := rr.Code; status != http.StatusOK {
    import "gopkg.in/square/go-jose.v2"
    import (
    in pure Go (no goyacc) and support for a printer.
    io.WriteString(w, `{"alive": true}`)
    it is treated as a hexadecimal. If it is prefixed with 0, it is
    item-size: 64
    item-size: 80
    jsontoml --help
    jww.INFO.Printf("information %q", response)
    jww.SetLogOutput(customWriter) 
    log.Fatal(http.ListenAndServe(":8000", r))
    log.Fatal(http.ListenAndServe(":8080", proxy))
    log.Fatal(http.ListenAndServe("localhost:8080", r))
    log.Fatal(srv.ListenAndServe())
    log.Println("shutting down")
    matter). The value can be any primitive: a string, number, boolean,
    max-items: 100
    max-items: 200
    object, or list.
    of objects can be created with repeated blocks, using
    os.Exit(0)
    other arrays, and objects. As an alternative, lists
    println(line.String())
    proxy := goproxy.NewProxyHttpServer()
    proxy.Verbose = true
    r := mux.NewRouter()
    r.HandleFunc("/", HomeHandler)
    r.HandleFunc("/", YourHandler)
    r.HandleFunc("/articles", ArticlesHandler)
    r.HandleFunc("/foo", fooHandler).Methods(http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodOptions)
    r.HandleFunc("/health", HealthCheckHandler)
    r.HandleFunc("/metrics/{type}", MetricsHandler)
    r.HandleFunc("/products", ProductsHandler)
    r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))
    r.Use(mux.CORSMethodMiddleware(r))
    raw = []byte(result.Raw)
    raw = json[result.Index:result.Index+len(result.Raw)]
    req, err := http.NewRequest("GET", "/health", nil)
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    return nil  // if its success otherwise return error
    return r.ProtoMajor == 0
    return strings.ToLower(json)
    return strings.ToUpper(json)
    return true
    rr := httptest.NewRecorder()
    service {
    signal.Notify(c, os.Interrupt)
    src="logo.png"
    src="logo.png" 
    srv := &http.Server{
    srv.Shutdown(ctx)
    terminates at the first `*/` found.
    this structure:
    token: 89h3f98hbwf987h3f98wenf89ehf
    tomljson --help
    tomll --help
    treated as an octal. Numbers can be in scientific notation: "1e10".
    tt := []struct{
    var dir string
    var wait time.Duration
    vars := mux.Vars(r)
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte("Gorilla!\n"))
    w.Write([]byte("foo"))
    w.WriteHeader(http.StatusOK)
    width="240" height="78" border="0" alt="GJSON">
    width="307" height="150" border="0" alt="BuntDB">
    with `EOF` on its own line ([here documents](https://en.wikipedia.org/wiki/Here_document)).
    {
    {"age": 44, "first": "Dale", "last": "Murphy"},
    {"age": 47, "first": "Jane", "last": "Murphy"}
    {"age": 68, "first": "Roger", "last": "Craig"},
    {"first": "Dale", "last": "Murphy", "age": 44, "nets": ["ig", "fb", "tw"]},
    {"first": "Jane", "last": "Murphy", "age": 47, "nets": ["ig", "tw"]}
    {"first": "Janet", "last": "Murphy", "age": 44}
    {"first": "Roger", "last": "Craig", "age": 68, "nets": ["fb", "tw"]},
    }
    }()
    })
    },
    }, {
    }`)
    }{
   "subAccountId": "100002",
   "userId": "sample@sample.com",
   something more useful
   which can be easily logged as well 
  "BoostFreq": 0,
  "BrandName": "AMD Ryzen 9 3950X 16-Core Processor",
  "Cache": {
  "CacheLine": 64,
  "Family": 23,
  "Features": [
  "Hz": 0,
  "LogicalCores": 32,
  "Model": 113,
  "PhysicalCores": 16,
  "SGX": {
  "ThreadsPerCore": 2,
  "VendorID": 2,
  "VendorString": "AuthenticAMD",
  "X64Level": 3
  "age": 37,
  "age":37,
  "attempt", 3,
  "backoff", time.Second,
  "children": ["Sara", "Alex", "Jack"],
  "children": ["Sara","Alex","Jack"],
  "fav.movie": "Deer Hunter",
  "friends": [
  "name": "Mitchell"
  "name": {
  "name": {"first": "Tom", "last": "Anderson"}
  "name": {"first": "Tom", "last": "Anderson"},
  "programmers": [
  "search_criteria": []string{"book", "glass", "pencil"},
  "type": "person",
  "url", url,
  "variable": {
  "widget": {
  * Arrays can be made by wrapping it in `[]`. Example:
  * Authorization option of `BasicAuth` and `Bearer` token
  * Automatic marshal and unmarshal for `JSON` and `XML` content type
  * Backoff Retry Mechanism with retry condition function [reference](retry_test.go)
  * Boolean values: `true`, `false`
  * Client settings like `Timeout`, `RedirectPolicy`, `Proxy`, `TLSClientConfig`, `Transport`, etc.
  * Cookies for your request and CookieJar support
  * Custom [Root Certificates](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.SetRootCertificate) and Client [Certificates](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.SetCertificates)
  * Development takes place at the master branch. Although the code in master should always compile and test successfully, it might break API's. I aim to maintain backwards compatibility, but sometimes API's and behavior might be changed to fix a bug.
  * Download/Save HTTP response directly into File, like `curl -o` flag. See [SetOutputDirectory](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.SetOutputDirectory) & [SetOutput](https://pkg.go.dev/github.com/go-resty/resty/v2#Request.SetOutput).
  * Easily mock Resty for testing, [for e.g.](#mocking-http-requests-using-httpmock-library)
  * Easy to upload one or more file(s) via `multipart/form-data`
  * Exposes Response reader without reading response (no auto-unmarshaling) if need be, see [how to use](https://github.com/go-resty/resty/issues/87#issuecomment-322100604)
  * GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS, etc.
  * Multi-line comments are wrapped in `/*` and `*/`. Nested block comments
  * Multi-line strings start with `<<EOF` at the end of a line, and end
  * Numbers are assumed to be base 10. If you prefix a number with 0x,
  * Option to specify expected `Content-Type` when response `Content-Type` header missing. Refer to [#92](https://github.com/go-resty/resty/issues/92)
  * Optionally allows GET request with payload, see [SetAllowGetMethodPayload](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.SetAllowGetMethodPayload)
  * Redirect Policies - see [how to use](#redirect-policy)
  * Request URL [Path Params (aka URI Params)](https://pkg.go.dev/github.com/go-resty/resty/v2#Request.SetPathParams)
  * Resty client HTTP & REST [Request](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.OnBeforeRequest) and [Response](https://pkg.go.dev/github.com/go-resty/resty/v2#Client.OnAfterResponse) middlewares
  * Resty design
  * Resty fully adapted to `go mod` capabilities since `v1.10.0` release.
  * Resty v1 series was using `gopkg.in` to provide versioning. `gopkg.in/resty.vX` points to appropriate tagged versions; `X` denotes version series number and it's a stable release for production use. For e.g. `gopkg.in/resty.v0`.
  * Resty v2 does not use `gopkg.in` service for library versioning.
  * Retry Mechanism [how to use](#retries)
  * SRV Record based request instead of Host URL
  * SRV Record based request instead of Host URL [how to use](resty_test.go#L1412)
  * Set request `ContentLength` value for all request or particular request
  * Simple and chainable methods for settings and request
  * Single line comments start with `#` or `//`
  * Strings are double-quoted and can contain any UTF-8 characters.
  * Supports registering external JSON library into resty, see [how to use](https://github.com/go-resty/resty/issues/76#issuecomment-314015250)
  * Values are assigned with the syntax `key = value` (whitespace doesn't
  * Well tested client library
  * [@fatih](https://github.com/fatih) - The rewritten HCL parser
  * [@vstakhov](https://github.com/vstakhov) - The original libucl parser
  * [Bazel support](#bazel-support)
  * [Request](https://pkg.go.dev/github.com/go-resty/resty/v2#Request) Body can be `string`, `[]byte`, `struct`, `map`, `slice` and `io.Reader` too
  * [Response](https://pkg.go.dev/github.com/go-resty/resty/v2#Response) object gives you more possibility
  * [THUMBAI](https://thumbai.app) - Go Mod Repository, Go Vanity Service and Simple Proxy Server.
  * [aah framework](https://aahframework.org) - A secure, flexible, rapid Go web framework.
  * [go-model](https://github.com/jeevatkm/go-model) - Robust & Easy to use model mapper and utility methods for Go `struct`.
  * [https://gopkg.in/yaml.v2](https://gopkg.in/yaml.v2)
  * `Request.SetContext` supported
  * etc (upcoming - throw your idea's [here](https://github.com/go-resty/resty/issues)).
  * v1.0 released and tagged on Sep 25, 2017. - Resty's first version was released on Sep 15, 2015 then it grew gradually as a very handy and helpful library. Its been a two years since first release. I'm very thankful to Resty users and its [contributors](https://github.com/go-resty/resty/graphs/contributors).
  * v1.12.0 [released](https://github.com/go-resty/resty/releases/tag/v1.12.0) and tagged on Feb 27, 2019.
  * v2.0.0 [released](https://github.com/go-resty/resty/releases/tag/v2.0.0) and tagged on Jul 16, 2019.
  * v2.12.0 [released](https://github.com/go-resty/resty/releases/tag/v2.12.0) and tagged on Mar 17, 2024.
  - 3
  - 4
  -v, --verbose           verbose output
  // Implement your logic here
  // Log the error, increment a metric, etc...
  // Structured context as loosely typed key-value pairs.
  // Structured context as strongly typed Field values.
  // return nil for continue redirect otherwise return error to stop/prevent redirect
  // variables goes here
  </p>
  <a href="https://academy.breakdev.org/evilginx-mastery"><img alt="Evilginx Mastery" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx_mastery.jpg" height="320" /></a>
  <a href="https://goreportcard.com/report/github.com/zeebo/blake3"><img src="https://goreportcard.com/badge/github.com/zeebo/blake3?style=flat-square" alt="Go Report Card" /></a>
  <a href="https://pkg.go.dev/github.com/zeebo/blake3"><img src="https://img.shields.io/badge/doc-reference-007d9b?logo=go&style=flat-square" alt="go.dev" /></a>
  <a href="https://sourcegraph.com/github.com/zeebo/blake3?badge"><img src="https://sourcegraph.com/github.com/zeebo/blake3/-/badge.svg?style=flat-square" alt="SourceGraph" /></a>
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <img alt="Screenshot" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/screen.png" height="320" />
  <p align="center">
  Body       :
  ConnIdleTime  : 0s
  ConnTime      : 381.709936ms
  DNSLookup     : 4.074657ms
  Error      : <nil>
  HandlerFunc(ArticleHandler).
  Host("www.example.com").
  IsConnReused  : false
  IsConnWasIdle : false
  Methods("GET").
  Name("article")
  Path("/articles/{category}/{id:[0-9]+}").
  Proto      : HTTP/2.0
  Queries("filter", "{filter}").
  Received At: 2020-09-14 15:35:29.784681 -0700 PDT m=+0.458137045
  RemoteAddr    : 3.221.81.55:443
  RequestAttempt: 1
  Schemes("http")
  ServerTime    : 75.414703ms
  Status     : 200 OK
  Status Code: 200
  TCPConnTime   : 77.428048ms
  TLSHandshake  : 299.623597ms
  This is to avoid differences in the interpretation of JOSE messages between
  Time       : 457.034718ms
  TotalTime     : 457.034718ms
  [case-insensitive matching](https://www.ietf.org/mail-archive/web/json/current/msg03763.html).
  ]
  ],
  ]}
  c: 2
  cache1:
  cache2:
  d:
  d: [3, 4]
  data, we prefer to reject it right away.
  func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2, err uintptr)
  func Syscall(trap, a1, a2, a3 uintptr) (r1, r2, err uintptr)
  func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr)
  go-jose and libraries written in other languages.
  if arg == "lower" {
  if arg == "upper" {
  if v, ok := err.(*resty.ResponseError); ok {
  input whenever we detect a duplicate. Rather than trying to work with malformed
  jacket: leather
  log.Fatalf("ERROR client certificate: %s", err)
  multierr comes with virtually no dependencies.
  multierr follows best practices in Go, and keeps your code idiomatic.
  multierr interoperates with the Go standard library's error APIs seamlessly:
  multierr is optimized for performance:
  return json
  return nil
  trousers: denim
  zap.Duration("backoff", time.Second),
  zap.Int("attempt", 3),
  zap.String("url", url),
  {
  }
  })
  },
 * CRITICAL
 * DEBUG
 * Debug, Trace & Info goto /dev/null
 * ERROR
 * Error and above is printed to the terminal (stdout)
 * FATAL
 * INFO
 * TRACE
 * WARN
 * Warn and above is logged (when a log file/io.Writer is provided)
 * Windows support via @mattn: [colorable](https://github.com/mattn/go-colorable)
 * [Fatih Arslan](https://github.com/fatih)
 * `AllSettings() : map[string]interface{}`
 * `AllowEmptyEnv(bool)`
 * `AutomaticEnv()`
 * `BindEnv(string...) : error`
 * `Get(key string) : interface{}`
 * `GetBool(key string) : bool`
 * `GetDuration(key string) : time.Duration`
 * `GetFloat64(key string) : float64`
 * `GetInt(key string) : int`
 * `GetIntSlice(key string) : []int`
 * `GetString(key string) : string`
 * `GetStringMap(key string) : map[string]interface{}`
 * `GetStringMapString(key string) : map[string]string`
 * `GetStringSlice(key string) : []string`
 * `GetTime(key string) : time.Time`
 * `IsSet(key string) : bool`
 * `SetEnvKeyReplacer(string...) *strings.Replacer`
 * `SetEnvPrefix(string)`
 * `Unmarshal(rawVal interface{}) : error`
 * `UnmarshalKey(key string, rawVal interface{}) : error`
 * `jsontoml`: Reads a JSON file and outputs a TOML representation.
 * config
 * default
 * env
 * explicit call to `Set`
 * flag
 * key/value store
 - [ ] appropriate `RemoteAddr` remapping
 - [x] TLS connection to proxy (customizeable) (e.g. `https://proxy.example.com`)
 - [x] customizeable for `Proxy-Authenticate`, with challenge-response semantics
 - [x] out of the box support for `Basic` auth
 - [x] unencrypted connection to proxy (e.g. `http://proxy.example.com:3128`
 :------------------------- | -------------------------------
 :------------------------- | :------------------------------
 AES key wrap               | A128KW, A192KW, A256KW
 AES, HMAC                  | []byte
 AES-CBC+HMAC               | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
 AES-GCM                    | A128GCM, A192GCM, A256GCM 
 AES-GCM key wrap           | A128GCMKW, A192GCMKW, A256GCMKW
 Algorithm(s)               | Corresponding types
 Compression                | Algorithm identifiers(s)
 Content encryption         | Algorithm identifier(s)
 DEFLATE (RFC 1951)         | DEF
 Direct encryption          | dir<sup>1</sup>
 ECDH, ECDSA                | *[ecdsa.PublicKey](http://golang.org/pkg/crypto/ecdsa/#PublicKey), *[ecdsa.PrivateKey](http://golang.org/pkg/crypto/ecdsa/#PrivateKey)
 ECDH-ES (direct)           | ECDH-ES<sup>1</sup>
 ECDH-ES + AES key wrap     | ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
 ECDSA                      | ES256, ES384, ES512
 Ed25519                    | EdDSA<sup>2</sup>
 EdDSA<sup>1</sup>          | [ed25519.PublicKey](https://godoc.org/golang.org/x/crypto/ed25519#PublicKey), [ed25519.PrivateKey](https://godoc.org/golang.org/x/crypto/ed25519#PrivateKey)
 HMAC                       | HS256, HS384, HS512
 Key encryption             | Algorithm identifier(s)
 RSA                        | *[rsa.PublicKey](http://golang.org/pkg/crypto/rsa/#PublicKey), *[rsa.PrivateKey](http://golang.org/pkg/crypto/rsa/#PrivateKey)
 RSA-OAEP                   | RSA-OAEP, RSA-OAEP-256
 RSA-PKCS#1v1.5             | RSA1_5
 RSASSA-PKCS#1v1.5          | RS256, RS384, RS512
 RSASSA-PSS                 | PS256, PS384, PS512
 Signing / MAC              | Algorithm identifier(s)
![Color](https://user-images.githubusercontent.com/438920/96832689-03b3e000-13f4-11eb-9803-46f4c4de3406.jpg)
![Go Version](https://img.shields.io/badge/go%20version-%3E=1.14-61CFDD.svg?style=flat-square)
![Gorilla Logo](http://www.gorillatoolkit.org/static/images/gorilla-icon-64.png)
![Incremental](/assets/incremental.svg)
![Large Full Buffer](/assets/large-full-buffer.svg)
![Small Full Buffer](/assets/small-full-buffer.svg)
![Status](https://github.com/elazarl/goproxy/workflows/Go/badge.svg)
![Travis CI Build Status](https://api.travis-ci.org/tidwall/btree.svg?branch=master)
![Viper](.github/logo.png?raw=true)
![Zap logo](assets/logo.png)
![](https://avatars0.githubusercontent.com/u/10216035?v=3&s=200)
![](https://raw.githubusercontent.com/mattn/go-colorable/gh-pages/bad.png)
![](https://raw.githubusercontent.com/mattn/go-colorable/gh-pages/good.png)
![afero logo-sm](https://cloud.githubusercontent.com/assets/173412/11490338/d50e16dc-97a5-11e5-8b12-019a300d0fcb.png)
![and_that__s_why_you_always_leave_a_note_by_jonnyetc-d57q7um](https://cloud.githubusercontent.com/assets/173412/11002937/ccd01654-847d-11e5-828e-12ebaf582eaf.jpg)
"/articles/technology/42"
"Command-line flag syntax" section below.
"age"                >> 37
"c?ildren.0"         >> "Sara"
"child*.2"           >> "Jack"
"children"           >> ["Sara","Alex","Jack"]
"children": ["Sara","Alex","Jack"],
"children.#"         >> 3
"children.1"         >> "Alex"
"children|@case:lower|@reverse"  >> ["jack","alex","sara"]
"children|@case:upper"           >> ["SARA","ALEX","JACK"]
"children|@reverse"           >> ["Jack","Alex","Sara"]
"children|@reverse|0"         >> "Jack"
"fav.movie": "Deer Hunter", "friends": [
"fav\.movie"         >> "Deer Hunter"
"friends.#.first"    >> ["Dale","Roger","Jane"]
"friends.1.last"     >> "Craig"
"name.last"          >> "Anderson"
# :zap: zap
# A taste of goproxy
# ARM features:
# About the project
# Alternative (more granular) approach to a DNS library
# Author
# Available Backends
# BLAKE3
# Benchmarks
# Beta Software
# Building
# Building `sys/unix`
# Evilginx 3.0
# Exponential Backoff [![GoDoc][godoc image]][godoc] [![Build Status][travis image]][travis] [![Coverage Status][coveralls image]][coveralls]
# Features
# File system notifications for Go
# Go JOSE 
# Go Modules
# Goals
# HCL
# HTTP CONNECT tunneling Go Dialer
# INI
# Introduction
# License
# Match
# More information
# Overview
# Pretty
# RegexpFs
# Safe JSON
# Type of handlers for manipulating connect/req/resp behavior
# Usage
# Users
# Using Afero
# What's New
# Why not Fiddler2?
# YAML support for the Go language
# color [![](https://github.com/fatih/color/workflows/build/badge.svg)](https://github.com/fatih/color/actions) [![PkgGoDev](https://pkg.go.dev/badge/github.com/fatih/color)](https://pkg.go.dev/github.com/fatih/color)
# cpuid
# go-colorable
# go-isatty
# go-toml
# go-vhost
# gorilla/mux
# gotenv
# license
# mapstructure [![Godoc](https://godoc.org/github.com/mitchellh/mapstructure?status.svg)](https://godoc.org/github.com/mitchellh/mapstructure)
# multierr [![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov]
# tinyqueue
# usage
#!/bin/bash
## API stability
## Afero Features
## Append-only File
## Author
## Available flags
## Backers
## Build Systems
## But Why?!
## But, really, why?
## Cache
## Caveats
## Challenge solvers
## Charts
## Check for the existence of a value
## Collate i18n Indexes
## Color
## Command line flag syntax
## Component files
## Composite Backends
## Config
## Contact
## Contribute
## Contributing
## Contribution
## Contributors
## Core Team
## Creator
## Credits
## Credits and License
## Custom Indexes
## Customized output
## Data Expiration
## Delete while iterating
## Deprecating a flag or its shorthand
## Descending Ordered Index
## Description
## Desired/possible backends
## Development Status: Stable
## Development status
## Disable sorting of flags
## Disclaimer
## Documentation
## Events
## Evilginx Mastery Training Course
## Example
## Examples
## FAQ
## Features
## Feedback
## Filtering Backends
## Full Example
## Generated files
## Get a value
## Get multiple values at once
## Get nested array values
## Getting Help
## Getting Started
## Getting Values From Viper
## GitHub Actions
## Guide
## Help
## Hidden flags
## History
## Implementing new providers
## Import
## Install
## Installation
## Installation and Upgrade
## Installing
## It might be beneficial for your project :smile:
## Iterate through an object or array
## JSON Indexes
## JSON Lines
## Latest Stable Release
## License
## List of all available functions
## Loosely Based Upon
## Mailing List
## Memory Backed Storage
## Menu
## Modifiers and path chaining 
## More info
## Multi Value Index
## Mutating or "Normalizing" Flag names
## Network Interfaces
## News
## Notes
## Official Gophish integration
## On-Demand TLS
## Opening a database
## Operating System Native
## Overview
## Path Syntax
## Performance
## Pretty
## Project History
## Putting Values into Viper
## Q & A
## Quick Start
## Record abstraction
## Related Projects
## Release Notes
## Repos using readline
## Requirements
## Result Type
## Setting and getting key/values
## Setting no option default values for flags
## Similar projects
## Simple Parse and Get
## So Good!
## Spatial Indexes
## Sponsors
## Status
## Step 1. Use it
## Step 1: Install Afero
## Step 2. Optionally configure JWW
## Step 2: Declare a backend
## Step 3: Use it like you would the OS package
## Storage
## Support
## Supported RFCs
## Supported features
## Supporting Go flags when using pflag
## Syntax
## Thanks
## The ACME Challenges
## Timing Tables
## ToDo
## Todo
## Too Bad!
## Tools
## Transactions
## Troubleshooting
## Ugly
## Unmarshal to a map
## Updated Git tags
## Usage
## Usage & Example
## Usage example
## Usage with gRPC
## Using Afero for Testing
## Using Afero's utility functions
## Validate JSON
## Versioning
## Viper or Vipers?
## What is Cast?
## What is Viper?
## What's in the name
## Why Viper?
## Why use Cast?
## Why?
## Why?!
## Working with Bytes
## Write-ups
## arm64 feature detection
## commandline
## example
## flags
## installing
### 64-bit integers
### Accessing nested keys
### Advanced introspection
### Another Scenario
### BasePathFs
### Behind a load balancer (or in a cluster)
### Built-in types
### BuntDB-Benchmark
### CacheOnReadFs
### Calling utilities directly
### Calling via Afero
### Can I use some of my own certificates while using CertMagic?
### Changing the thresholds
### Check CPU microarch level
### CopyOnWriteFs()
### Custom fprint functions (FprintFunc)
### Custom modifiers
### Custom print functions (PrintFunc)
### DNS Challenge
### Decoding custom formats
### Development and Testing
### Disable/Enable color
### Docker image
### Does CertMagic obtain SAN certificates?
### Does Viper support case sensitive keys?
### Durability and fsync
### Environment Overrides
### Establishing Defaults
### Example
### Examples
### Extracting a sub-tree
### Fuzzing
### GCSFs
### Graceful Shutdown
### HTTP Challenge
### Handling CORS Requests
### Homebrew
### How can I listen on ports 80 and 443? Do I have to run as root?
### HttpFs
### Included Batteries
### Insert into noncolor strings (SprintFunc)
### Is it safe to concurrently read and write to a viper?
### Iterating
### JSON Output:
### Large
### Low-level API usage
### Marshalling to string
### Matching Routes
### MemMapFs
### Middleware
### Mix and reuse colors
### Modifier arguments
### Multipart File(s) upload
### New Build System (currently for `GOOS == "linux"`)
### No ASM
### Old Build System (currently for `GOOS != "linux"`)
### OsFs
### Package Overview
### Plug into existing code
### Read-only Transactions
### Read/write Transactions
### ReadOnlyFs
### Reading Config Files
### Reading Config from io.Reader
### Registered URLs
### Registering and Using Aliases
### Remote Key/Value Store Example - Encrypted
### Remote Key/Value Store Example - Unencrypted
### Remote Key/Value Store Support
### Run tests
### Setting Overrides
### Setting a log file
### SftpFs
### Small
### Spatial bracket syntax
### Standard colors
### Static Files
### Supported algorithms
### Supported key types
### TLS-ALPN Challenge
### Testing Handlers
### Throw a Panic
### Unmarshaling
### Usage
### Use your own output (io.Writer)
### Versions
### Walking Routes
### Watching Changes in etcd - Unencrypted
### Watching and re-reading config files
### Wildcard certificates
### Working with Environment Variables
### Working with Flags
### Working with multiple vipers
### Writing Config Files
### [API Documentation](https://godoc.org/github.com/inconshreveable/go-vhost)
### `zerrors_${GOOS}_${GOARCH}.go`
### `zsyscall_${GOOS}_${GOARCH}.go`
### `zsysnum_${GOOS}_${GOARCH}.go`
### `ztypes_${GOOS}_${GOARCH}.go`
### asm files
### internal/mkmerge
### k-Nearest Neighbors
### mkerrors.sh
### mksyscall.go
### mksysnum
### types files
### x86 & amd64 
#### 13 Feb 2018
#### Advanced use
#### Allow GET request with Payload
#### Bazel Support
#### Certificate authority
#### Consul
#### Custom Root Certificates and Client Certificates
#### Custom Root Certificates and Client Certificates from string
#### Defaults
#### Enhanced GET
#### Env example
#### Firestore
#### Flag interfaces
#### Getting a tls.Config
#### InMemoryFile
#### Mocking http requests using [httpmock](https://github.com/jarcoal/httpmock) library
#### OnError Hooks
#### Override JSON & XML Marshal/Unmarshal
#### Please run `git pull --tags` to update the tags. See [below](#updated-git-tags) why.
#### Providing an email address
#### Proxy Settings
#### Rate limiting
#### Redirect Policy
#### Remaining Client Settings & its Options
#### Request URL Path Params
#### Request and Response Middleware
#### Retries
#### Sample DELETE, HEAD, OPTIONS
#### Sample Form submission
#### Sample PATCH
#### Sample PUT
#### Save HTTP Response into File
#### Serving HTTP handlers with HTTPS
#### Simple GET
#### Starting a TLS listener
#### Supported Go Versions
#### The `Config` type
#### Unix Socket
#### Using File directly from Path
#### Using io.Reader
#### Various POST method combinations
#### Wanna Multiple Clients
#### etcd
##### Custom Redirect Policy
##### Memory reduction with Free
$ brew install cpuid
$ buntdb-benchmark -q
$ crypt get -plaintext /config/hugo.json
$ crypt set -plaintext /config/hugo.json /Users/hugo/settings/config.json
$ go get -u github.com/magiconair/properties
$ go get -u github.com/tidwall/buntdb
$ go get -u github.com/tidwall/gjson
$ go get -u github.com/tidwall/pretty
$ go get github.com/bketelsen/crypt/bin/crypt
$ go get github.com/caddyserver/certmagic
$ go get github.com/mattn/go-colorable
$ go get github.com/mattn/go-isatty
$ go get github.com/mitchellh/mapstructure
$ go get gopkg.in/ini.v1
$ sudo setcap cap_net_bind_service=+ep /path/to/your/binary
'P' to the name of any function that defines a flag.
(Events are new and still experimental, so they may change.)
([`jose-util`](https://github.com/square/go-jose/tree/v2/jose-util))
([branch](https://github.com/square/go-jose/tree/v2),
(c) 2020 Matthew Holt
(for example if the output were piped directly to `less`).
(majority of cases), those features are implemented and the API unlikely to
(not like) operators.
(see [Go Release Policy](https://golang.org/doc/devel/release.html#policy)).
)
*   Trying ::1...
* 103{4,5} - DNS standard
* 1183 - ISDN, X25 and other deprecated records
* 1348 - NSAP record (removed the record)
* 1876 - LOC record
* 1982 - Serial Arithmetic
* 1983 Original algorithm and test code by Antonin Guttman and Michael Stonebraker, UC Berkely
* 1994 ANCI C ported from original test code by Melinda Green 
* 1995 - IXFR
* 1995 Sphere volume fix for degeneracy problem submitted by Paul Brook
* 1996 - DNS notify
* 2004 Templated C++ port by Greg Douglas
* 2016 Go port by Josh Baker
* 2018 Added kNN and merged in some of the RBush logic by Vladimir Agafonkin
* 2065 - DNSSEC (updated in later RFCs)
* 2136 - DNS Update (dynamic updates)
* 2181 - RRset definition - there is no RRset type though, just []RR
* 2537 - RSAMD5 DNS keys
* 2671 - EDNS record
* 2782 - SRV record
* 2845 - TSIG record
* 2915 - NAPTR record
* 2929 - DNS IANA Considerations
* 3110 - RSASHA1 DNS keys
* 3123 - APL record
* 3225 - DO bit (DNSSEC OK)
* 340{1,2,3} - NAPTR record
* 3445 - Limiting the scope of (DNS)KEY
* 3597 - Unknown RRs
* 4025 - A Method for Storing IPsec Keying Material in DNS
* 403{3,4,5} - DNSSEC + validation functions
* 4255 - SSHFP record
* 4343 - Case insensitivity
* 4408 - SPF record
* 4509 - SHA256 Hash in DS
* 4592 - Wildcards in the DNS
* 4635 - HMAC SHA TSIG
* 4701 - DHCID
* 4892 - id.server
* 5001 - NSID
* 5155 - NSEC3 record
* 5205 - HIP record
* 5702 - SHA2 in the DNS
* 5936 - AXFR
* 5966 - TCP implementation recommendations
* 6605 - ECDSA
* 6725 - IANA Registry Update
* 6742 - ILNP DNS
* 6840 - Clarifications and Implementation Notes for DNS Security
* 6844 - CAA record
* 6891 - EDNS0 update
* 6895 - DNS IANA considerations
* 6944 - DNSSEC DNSKEY Algorithm Status
* 6975 - Algorithm Understanding in DNSSEC
* 7043 - EUI48/EUI64 records
* 7314 - DNS (EDNS) EXPIRE Option
* 7477 - CSYNC RR
* 7553 - URI record
* 7828 - edns-tcp-keepalive EDNS0 Option
* 7858 - DNS over TLS: Initiation and Performance Considerations
* 7871 - EDNS0 Client Subnet
* 7873 - Domain Name System (DNS) Cookies
* 8080 - EdDSA for DNSSEC
* 8499 - DNS Terminology
* 8659 - DNS Certification Authority Authorization (CAA) Resource Record
* 8777 - DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery
* 8914 - Extended DNS Errors
* 8976 - Message Digest for DNS Zones (ZONEMD RR)
* A set of interfaces to encourage and enforce interoperability between backends
* A set of utility functions ported from io, ioutil & hugo to be afero aware
* A single consistent API for accessing a variety of filesystems
* AXFR/IXFR
* An atomic cross platform memory backed file system
* Avoid security issues and permissions
* BSD / OSX: sysctl variables "kern.maxfiles" and "kern.maxfilesperproc", reaching these limits results in a "too many open files" error.
* Client side programming
* Connected to localhost (::1) port 8080 (#0)
* Connection #0 to host localhost left intact
* DNS name compression
* DNS over TLS (DoT): encrypted connection between client and server over TCP
* DNSSEC: signing, validating and key generation for DSA, RSA, ECDSA and Ed25519
* Define different filesystems for different parts of your application.
* Dump contents with passwords and secrets obscured
* EDNS0, NSID, Cookies
* Easily navigate TOML structure using Tree
* Evaluate fmt.Formatter interface
* Far more control. 'rm -rf /' with confidence
* Fast
* Fast;
* GRONG - <https://github.com/bortzmeyer/grong>
* I would like to keep this library as small as possible.
* If proposed change is not a common use case, I will probably not accept it.
* If you do not specify any methods, then:
* Interoperation between a variety of file system types
* It implements the `http.Handler` interface so it is compatible with the standard `http.ServeMux`.
* KISS;
* Line & column position data for all parsed elements
* Linux: /proc/sys/fs/inotify/max_user_watches contains the limit, reaching this limit results in a "no space left on device" error.
* Load TOML documents from files and string data
* Marshaling and unmarshaling to and from data structures
* Much faster than performing I/O operations on disk
* NSD - <https://nlnetlabs.nl/projects/nsd/about/>
* Net::DNS - <http://www.net-dns.org/>
* No Chmod support - The GCS ACL could probably be mapped to *nix style permissions but that would add another level of complexity and is ignored in this version.
* No Chtimes support - Could be simulated with attributes (gcs a/m-times are set implicitly) but that's is left for another version.
* No test cleanup needed
* Not thread safe - Also assumes all file operations are done through the same instance of the GcsFs. File operations between different GcsFs instances are not guaranteed to be consistent.
* Object deserialization uses case-sensitive member name matching instead of
* Please don't send a PR without opening an issue and discussing it first.
* RFC 1035 zone file parsing ($INCLUDE, $ORIGIN, $TTL and $GENERATE (for all record types) are supported
* Registered URLs can be built, or "reversed", which helps maintaining references to resources.
* Requests can be matched based on URL host, path, path prefix, schemes, header and query values, HTTP methods or using custom matchers.
* Routes can be used as subrouters: nested routes are only tested if the parent route matches. This is useful to define groups of routes that share common conditions like a host, a path prefix or other repeated attributes. As a bonus, this optimizes request matching.
* S3
* SSH
* SafeWriteConfig - writes the current viper configuration to the predefined path. Errors if no predefined path. Will not overwrite the current config file, if it exists.
* SafeWriteConfigAs - writes the current viper configuration to the given filepath. Will not overwrite the given file, if it exists.
* Save/Return previous values
* Server side programming (mimicking the net/http package)
* Small API. If it's easy to code in Go, don't make a function for it.
* Specialized backends which modify existing filesystems (Read Only, Regexp filtered)
* Support for compositional (union) file systems by combining multiple file systems acting as one
* Syntax errors contain line and column numbers
* TCP_NODELAY set
* TSIG, SIG(0)
* Test setup is far more easier to do
* The middleware will set the `Access-Control-Allow-Methods` header to all the method matchers (e.g. `r.Methods(http.MethodGet, http.MethodPut, http.MethodOptions)` -> `Access-Control-Allow-Methods: GET,PUT,OPTIONS`) on a route
* UDP/TCP queries, IPv4 and IPv6
* URL hosts, paths and query values can have variables with an optional regular expression.
* Use Afero for mock filesystems while testing
* Use the interfaces alone to define your own file system.
* When deserializing a JSON object, we check for duplicate keys and reject the
* Wrapper for go 1.16 filesystem abstraction `io/fs.FS`
* Wrapper for the OS packages.
* WriteConfig - writes the current viper configuration to the predefined path, if exists. Errors if no predefined path. Will overwrite the current config file, if it exists.
* WriteConfigAs - writes the current viper configuration to the given filepath. Will overwrite the given file, if it exists.
* You will still need to use your own CORS handler to set the other CORS headers such as `Access-Control-Allow-Origin`
* [BloomApi](https://www.bloomapi.com/)
* [Clairctl](https://github.com/jgsqware/clairctl)
* [Demo](example/readline-demo/readline-demo.go)
* [Docker Notary](https://github.com/docker/Notary)
* [EMC RexRay](http://rexray.readthedocs.org/en/stable/)
* [Examples](#examples)
* [Full Example](#full-example)
* [Graceful Shutdown](#graceful-shutdown)
* [Handling CORS Requests](#handling-cors-requests)
* [Hugo](http://gohugo.io)
* [Install](#install)
* [Matching Routes](#matching-routes)
* [Mercure](https://mercure.rocks)
* [Middleware](#middleware)
* [Nanobox](https://github.com/nanobox-io/nanobox)/[Nanopack](https://github.com/nanopack)
* [Query support similar to JSON-Path](query/)
* [Registered URLs](#registered-urls)
* [Shortcut](doc/shortcut.md)
* [Static Files](#static-files)
* [Testing Handlers](#testing-handlers)
* [Walking Routes](#walking-routes)
* [doctl](https://github.com/digitalocean/doctl)
* [fsevents](https://github.com/fsnotify/fsevents)
* [http://weibo.com/2145262190](http://weibo.com/2145262190)
* [https://twitter.com/chzyer](https://twitter.com/chzyer)
* [jaqx0r](https://github.com/jaqx0r)
* [mbertschler](https://github.com/mbertschler)
* [notify](https://github.com/rjeczalik/notify)
* [spf13](https://github.com/spf13)
* [xor-gate](https://github.com/xor-gate)
* `tomljson`: Reads a TOML file and outputs its JSON representation.
* `tomll`: Reads TOML files and lints them.
* http://www.dns-lg.com/
* http://www.dnsinspect.com/
* http://www.statdns.com/
* https://addr.tools/
* https://blitiri.com.ar/p/dnss ([github mirror](https://github.com/albertito/dnss))
* https://dnscheck.tools/
* https://dnslookup.org
* https://dnssectest.net/
* https://domainr.com/
* https://fleetdeck.io/
* https://github.com/DevelopersPL/godnsagent
* https://github.com/Luzilla/dnsbl_exporter
* https://github.com/StackExchange/dnscontrol/
* https://github.com/StalkR/dns-reverse-proxy
* https://github.com/abh/geodns
* https://github.com/baidu/bfe
* https://github.com/bamarni/dockness
* https://github.com/benschw/dns-clb-go
* https://github.com/bodgit/tsig
* https://github.com/chuangbo/jianbing-dictionary-dns
* https://github.com/coredns/coredns
* https://github.com/corny/dnscheck for <http://public-dns.info/>
* https://github.com/duedil-ltd/discodns
* https://github.com/egbakou/domainverifier
* https://github.com/fcambus/rrda
* https://github.com/fcambus/statzone
* https://github.com/fffaraz/microdns
* https://github.com/folbricht/routedns
* https://github.com/fortio/dnsping
* https://github.com/hashicorp/consul
* https://github.com/ipdcode/hades <https://jd.com>
* https://github.com/jedisct1/dnscrypt-proxy
* https://github.com/jedisct1/rpdns
* https://github.com/kenshinx/godns
* https://github.com/looterz/grimd
* https://github.com/markdingo/autoreverse
* https://github.com/mehrdadrad/mylg
* https://github.com/miekg/exdns
* https://github.com/miekg/unbound
* https://github.com/oif/apex
* https://github.com/peterzen/goresolver
* https://github.com/phamhongviet/serf-dns
* https://github.com/rs/dnstrace
* https://github.com/semihalev/sdns
* https://github.com/skynetservices/skydns
* https://github.com/slackhq/nebula
* https://github.com/tianon/rawdns
* https://github.com/v2fly/v2ray-core (test only)
* https://github.com/wintbiit/NineDNS
* https://github.com/xor-gate/sshfp
* https://kuma.io/
* https://mesosphere.github.io/mesos-dns/
* https://ping.sx/dig
* https://render.com
* https://router7.org/
* https://www.dnsperf.com/
* https://www.misaka.io/services/dns
* https://zonedb.org/
* k-takata: base idea for IsCygwinTerminal
* ldns - <https://nlnetlabs.nl/projects/ldns/about/>
* live watching and re-reading of config files (optional)
* reading from JSON, TOML, YAML, HCL, envfile and Java properties config files
* reading from buffer
* reading from command line flags
* reading from environment variables
* reading from remote config systems (etcd or Consul), and watching changes
* setting defaults
* setting explicit values
**"Ad"** is a prefix meaning "to".
**Client Level Proxy** settings applied to all the request
**Disclaimer**: This library contains encryption software that is subject to
**Do I have to watch the Error and Event channels in a separate goroutine?**
**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.
**Example #1**: You want -, _, and . in flags to compare the same. aka --my-flag == --my_flag == --my.flag
**Example #1**: You want to deprecate a flag named "badflag" as well as inform the users what flag they should use instead.
**Example #2**: You want to alias two flags. aka --old-flag-name == --new-flag-name
**Example #2**: You want to keep a flag name "noshorthandflag" but deprecate its shortname "n".
**Example**:
**Example**: You have a flag named "secretFlag" that you need for internal use only and don't want it showing up in help text, or for its usage text to be available.
**Example**: You want to add the Go flags to the `CommandLine` flagset
**Go configuration with fangs!**
**How many files can be watched at once?**
**Important:** Viper configuration keys are case insensitive.
**Make sure you add all of the configPaths prior to calling `WatchConfig()`**
**NOTE:** This module is for _getting_ certificates, not _managing_ certificates. Most users probably want certificate _management_ (keeping certificates renewed) rather than to interface directly with ACME. Developers who want to use certificates in their long-running Go programs should use [CertMagic](https://github.com/caddyserver/certmagic) instead; or, if their program is not written in Go, [Caddy](https://caddyserver.com/) can be used to manage certificates (even without running an HTTP or TLS server).
**Note**: We use a forked version of the `encoding/json` package from the Go
**Note:** Always check the return value of `Sub`. It returns `nil` if a key cannot be found.
**Note:** Viper uses [Go Modules](https://github.com/golang/go/wiki/Modules) to manage dependencies.
**Notice:** The longitude is the Y axis and is on the left, and latitude is the X axis and is on the right.
**Output**:
**When I watch a directory, are all subdirectories watched as well?**
**When a file is moved to another directory is it still being watched?**
**Why am I receiving multiple events for the same file on OS X?**
**Why don't notifications work with NFS filesystems or filesystem in userspace (FUSE)?**
**[Instructions for adding new providers](https://github.com/libdns/libdns/wiki/Implementing-providers)** are on this repo's wiki. Please feel free to contribute.
**[OctoDNS](https://github.com/github/octodns)** is a suite of tools written in Python for managing DNS. However, its approach is a bit heavy-handed when all you need are small, incremental changes to a zone:
**[StackExchange/dnscontrol](https://github.com/StackExchange/dnscontrol)** is written in Go, but is similar to OctoDNS in that it tends to obliterate your entire zone and replace it with your input. Again, this is very useful if you are maintaining your own master list of records, but doesn't do well for simply adding or removing records.
**[go-acme/lego](https://github.com/go-acme/lego)** has support for a huge number of DNS providers (75+!), but their APIs are only capable of setting and deleting TXT records for ACME challenges.
**_Before using this library, your domain names MUST be pointed (A/AAAA records) at your server (unless you use the DNS challenge)!_**
**`libdns`** takes inspiration from the above projects but aims for a more generally-useful set of APIs that homogenize pretty well across providers. In contrast to the above projects, libdns can add, set, delete, and get arbitrary records from a zone without obliterating it (although syncing up an entire zone is also possible!). Its APIs also include context so long-running calls can be cancelled early, for example to accommodate on-line config changes downstream. libdns interfaces are also smaller and more composable. Additionally, libdns can grow to support a nearly infinite number of DNS providers without added bloat, because each provider implementation is a separate Go module, which keeps your builds lean and fast.
**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under BSD-3 license.
**tl;dr:** No.
*/
*LatLon: "33.5123 -112.2693"*
*Min LatLon: "33.51 -112.26", Max LatLon: "33.67 -112.18"*
*Min XY: "10x15", Max XY: "20x25"*
*Min XYZ: "10x15x12", Max XYZ: "20x25x18"*
*NOTE [since 1.6]:* You can also have a file without an extension and specify the format programmaticaly. For those configuration files that lie in the home of the user without any extension like `.bashrc`
*Please note that prior to v1.3.0, queries used the `#[...]` brackets. This was
*The full list of `@pretty` options are `sortKeys`, `indent`, `prefix`, and `width`. 
*There's also the [GetMany](#get-multiple-values-at-once) function to get multiple values at once, and [GetBytes](#working-with-bytes) for working with JSON byte slices.*
*These are the results from running the benchmarks on a MacBook Pro 15" 2.8 GHz Intel Core i7:*
*These benchmarks were run on a MacBook Pro 16" 2.4 GHz Intel Core i9 using Go 1.17 and can be found [here](https://github.com/tidwall/gjson-benchmarks).*
*These benchmarks were run on a MacBook Pro 2.4 GHz 8-Core Intel Core i9.*
*XY: "10x15"*
*all of them*
- **2D point:** `[10 15]`
- **2D rectangle:** `[10 15],[20 25]`
- **3D rectangle:** `[10 15 12],[20 25 18]`
- **AutoShrinkDisabled** turns off automatic background shrinking. Default is false.
- **AutoShrinkMinSize** defines the minimum size of the aof file before an automatic shrink can occur. Default is 32MB.
- **AutoShrinkPercentage** is used by the background process to trigger a shrink of the aof file when the size of the file is larger than the percentage of the result of the previous shrunk file. For example, if this value is 100, and the last shrink process resulted in a 100mb file, then the new aof file must be 200mb before a shrink is triggered. Default is 100.
- **Idiomatic**:
- **Interoperable**:
- **Lightweight**:
- **LonLat bounding box:** `[-112.26 33.51],[-112.18 33.67]`
- **LonLat point:** `[-112.2693 33.5123]`
- **Performant**:
- **SyncPolicy** adjusts how often the data is synced to disk. This value can be Never, EverySecond, or Always. Default is EverySecond.
- **`acme`** is a low-level RFC 8555 implementation that provides the fundamental ACME operations, mainly useful if you have advanced or niche requirements.
- **`acmez`** is a high-level wrapper for getting certificates. It implements the ACME order flow described in RFC 8555 including challenge solving using pluggable solvers.
- **`cached_unmanaged_cert`** An unmanaged certificate was cached
- **`cert_failed`** An attempt to obtain a certificate failed
- **`cert_obtained`** A certificate was successfully obtained
- **`cert_obtaining`** A certificate is about to be obtained
- **`cert_ocsp_revoked`** A certificate's OCSP indicates it has been revoked
- **`tls_get_certificate`** The GetCertificate phase of a TLS handshake is under way
- 1.10.3+
- 1.11+
- 1.9.7+
- ACID semantics with locking [transactions](#transactions) that support rollbacks
- All [libdns](https://github.com/libdns) DNS providers work out-of-the-box
- Any and all changes to the code must be documented
- Automatic OCSP stapling ([done right](https://gist.github.com/sleevi/5efe9ef98961ecfb4da8#gistcomment-2336055)) [keeps your sites online!](https://twitter.com/caddyserver/status/1234874273724084226)
- Certificate revocation (please, only if private key is compromised)
- Challenge plasticity (randomized challenges, and will retry others if one fails)
- Context cancellation (suitable for high-frequency config changes or reloads)
- Create [custom indexes](#custom-indexes) for any data type
- Cross-platform support! Mac, Windows, Linux, BSD, Android...
- Descend* functions for iterating backwards.
- Distributed solving of all challenges (works behind load balancers)
- Efficient solving of large SAN lists (e.g. for slow DNS record propagation)
- Embeddable with a [simple API](https://godoc.org/github.com/tidwall/buntdb)
- External Account Binding (EAB) support
- Flexible [iteration](#iterating) of data; ascending, descending, and ranges
- Full control over almost every aspect of the system
- Fully automated certificate management including issuance and renewal
- HTTP->HTTPS redirects
- Highly flexible and customizable
- I make no attempt to get precise measurements (cpu throttling, noisy environment, etc.) so please benchmark on your own systems.
- I tried my best to make them benchmark the same thing, but who knows? :smile:
- In-memory database for [fast reads and writes](#performance)
- Index fields inside [JSON](#json-indexes) documents
- Iteration performance boost.
- Keep sections and keys in order as you parse and save.
- License text and copyright notices must stay intact and be included with distributions
- Load from multiple data sources(file, `[]byte`, `io.Reader` and `io.ReadCloser`) with overwrites.
- Manipulate sections, keys and comments with ease.
- Most robust error handling of _any_ ACME client
- Multiple issuers supported: get certificates from multiple sources/CAs for redundancy and resiliency
- Must-Staple (optional; not default)
- One-line, fully managed HTTPS servers
- One-time private keys by default (new key for each cert) to discourage pinning and reduce scope of key compromise
- Option to evict old items with an [expiration](#data-expiration) TTL
- Optional event hooks for observation
- Pluggable key sources
- Pluggable storage backends (default: file system)
- Powered by [ACMEz](https://github.com/mholt/acmez), _the_ premier ACME client library for Go
- Private and internal use is allowed
- Read and **WRITE** comments of sections and keys.
- Read and convert values to Go types.
- Read with auto-increment key names.
- Read with multiple-line values.
- Read with parent-child sections.
- Read with recursion values.
- Read with tons of helper methods.
- Robust to external errors
- Scales to hundreds of thousands of names/certificates per instance
- Simple, elegant Go API
- Smart retries (resilient against network and server hiccups)
- Solves all 3 common ACME challenges: HTTP, TLS-ALPN, and DNS (and capable of others)
- Structured error values ("problems" as defined in RFC 7807)
- Support for [multi value indexes](#multi-value-index); Similar to a SQL multi column index
- Supports "on-demand" issuance of certificates (during TLS handshakes!)
- Supports niche aspects of RFC 8555 (such as alt cert chains and account key rollover)
- Tested with multiple ACME CAs (more than just Let's Encrypt)
- The Rust benchmarks below are all single-threaded to match this Go implementation.
- The author owns the copyright to this code
- The client failed to send the request due to connection timeout, TLS handshake failure, etc...
- The request was retried the maximum amount of times, and still failed.
- These benchmarks are run on an i7-6700K which does not support AVX-512, so Rust is limited to use AVX2 at sizes above 8 kib.
- Thoroughly documented with spec citations
- Tight codebase, under 2K loc using the `cloc` command
- Use in conjunction with your own certificates
- Use, distribute, and modify the software freely
- User defined context.
- Utility functions for solving challenges
- Wildcard certificates
- Works with any certificate authority (CA) compliant with the ACME specification RFC 8555
- Written in Go, a language with memory-safety guarantees
- [API Documentation](https://gowalker.org/gopkg.in/ini.v1)
- [Built-in types](#built-in-types) that are easy to get up & running; String, Uint, Int, Float
- [Collate i18n Indexes](#collate-i18n-indexes) using the optional [collate package](https://github.com/tidwall/collate)
- [Contributing](#contributing)
- [Credits and License](#credits-and-license)
- [Durable append-only file](#append-only-file) format for persistence
- [Features](#features)
- [Getting Started](https://ini.unknwon.io/docs/intro/getting_started)
- [Installation](#installation)
- [Project History](#project-history)
- [Requirements](#requirements)
- [Spatial indexing](#spatial-indexes) for up to 20 dimensions; Useful for Geospatial data
- [Usage](#usage)
- [`CacheUnmanagedCertificatePEMBytes()`](https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc#Config.CacheUnmanagedCertificatePEMBytes)
- [`CacheUnmanagedCertificatePEMFile()`](https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc#Config.CacheUnmanagedCertificatePEMFile)
- [`CacheUnmanagedTLSCertificate()`](https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc#Config.CacheUnmanagedTLSCertificate)
- [`RecordAppender`](https://pkg.go.dev/github.com/libdns/libdns#RecordAppender) to append new records.
- [`RecordDeleter`](https://pkg.go.dev/github.com/libdns/libdns#RecordDeleter) to delete records.
- [`RecordGetter`](https://pkg.go.dev/github.com/libdns/libdns#RecordGetter) to list records.
- [`RecordSetter`](https://pkg.go.dev/github.com/libdns/libdns#RecordSetter) to set (create or change existing) records.
- `@flatten`: Flattens an array.
- `@fromstr`: Converts a string from json. Unwraps a json string.
- `@group`: Groups arrays of objects. See [e4fc67c](https://github.com/tidwall/gjson/commit/e4fc67c92aeebf2089fabc7872f010e340d105db).
- `@join`: Joins multiple objects into a single object.
- `@keys`: Returns an array of keys for an object.
- `@pretty`: Make the json document more human readable.
- `@reverse`: Reverse an array or the members of an object.
- `@this`: Returns the current element. It can be used to retrieve the root element.
- `@tostr`: Converts json to a string. Wraps a json string.
- `@ugly`: Remove all whitespace from a json document.
- `@valid`: Ensure the json document is valid.
- `@values`: Returns an array of values for an object.
- `Always` - fsync after every write, very durable, slower
- `EverySecond` - fsync every second, fast and safer, this is the default
- `Never` - fsync is managed by the operating system, less safe
- `gotenv.Apply`
- `gotenv.Load`
- `gotenv.OverApply`
- `gotenv.OverLoad`
- go
- skateboarding
- snowboarding
---
--- m dump:
--- m:
--- t dump:
--- t:
-------
------------
-------------
-----------------
--------------------
----------------------
-------------------------------------------------------------------------------
--flag    // boolean flags, or flags with no option default values
--flag x  // only on flags without a default value
--flag=x
-abc
-abcs "hello"
-abcs1234
-absd="hello"
-b true is INVALID
-f
-f=true
-n 1234
-n1234
-n=1234
..#                   >> 4
..#(name="May").age   >> 57
..#.name              >> ["Gilbert","Alexa","May","Deloise"]
...
...and finally, it is possible to combine several matchers in a single route:
...and the result will be a `url.URL` with the following path:
...and the route will match both requests with a Content-Type of `application/json` as well as `application/text`
...or HTTP methods:
...or URL schemes:
...or header values:
...or query values:
...or to use a custom matcher function:
..1                   >> {"name": "Alexa", "age": 34}
..3                   >> {"name": "Deloise", "age": 44}
/*
/* Output
//   * Fallback is plain text content type
//   * For struct and map data type defaults to 'application/json'
//   Composed URL - /v1/users/sample@sample.com/100002/details
// "/articles/technology/42"
// "/products/"
// "/products/{key}/"
// "/products/{key}/details"
// "http://news.example.com/"
// "http://news.example.com/articles/technology/42"
// (some providers have caveats; see their package documentation)
// ...
// ... and so on!
// 1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
// 2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
// 3: {"name":{"first":"Carol","last":"Anderson"},"age":52}
// 4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
// 5: {"name":{"first":"Sam","last":"Anderson"},"age":51}
// 6: {"name":{"first":"Melinda","last":"Prichard"},"age":44}
// A newline will be appended automatically
// Add handlers to httpsHandlers 
// Add handlers to reqHandlers
// Add handlers to respHandlers
// Adding Client Certificates, you add one or more certificates
// Allow GET request with Payload. This is disabled by default.
// Assign Client Redirect Policy. Create one as per you need
// Assign Client TLSClientConfig
// Basic Auth for all request
// Bearer Auth Token for all request
// Bend it as per your need!!!
// Client 1
// Client 2
// Config file found and successfully parsed
// Cookies for all request
// Create SprintXxx functions to mix strings with other non-colorized strings:
// Create a Go's http.Transport so we can set it in resty.
// Create a Resty Client
// Create a custom print function for convenience
// Create a new color object
// Custom Root certificates from string
// Custom Root certificates, just supply .pem file.
// DELETE a article
// DELETE a articles with payload/body as a JSON string
// Define our struct
// Enable debug mode
// Enabling Content length value for all request
// Example of registering json-iterator
// Explore response object
// Explore trace info
// First make a pointer to a Cache as we need to reference the same Cache in
// Followed by profile update
// Form data for all request. Typically used with POST and PUT
// GET / HTTP/1.1
// Get the underlying HTTP Client and set it to Mock
// GetConfigForCert below.
// HEAD of resource
// HTTP response gets saved into file, similar to curl -o flag
// Headers for all request
// Here you go!
// Host URL for all request. So you can use relative URL in the request
// Host: example.com
// If necessary, you can force response content type to tell Resty to parse a JSON response into your struct
// Import resty into your code and refer it as `resty`.
// Initialize it somewhere
// Matches a dynamic subdomain.
// Middleware function, which will be called for each request
// Mix up foreground and background colors, create new mixes!
// Mix up multiple attributes
// Mix up with multiple attributes
// Multi value form data
// Multipart of form fields and files
// Multiple files scenario
// NOTE: using Apply existing value will be reserved
// NOTE: using OverApply existing value will be overridden
// No need to set auth token, error, if you have client level settings
// No need to set auth token, if you have client level settings
// No need to set content type, if you have client level setting
// No need to write the host's URL on the request, just the path.
// Note: This is one sample of PUT method usage, refer POST for more combination
// Note: output directory path is not used for absolute path
// Note: resty detects Content-Type for request body/payload if content type header is not set.
// Note: struct fields must be public in order for unmarshal to
// OPTIONS of resource
// OR using absolute path
// One can set custom root-certificate. Refer: http://golang.org/pkg/crypto/tls/#example_Dial
// Only matches if domain is "www.example.com".
// Or as one step
// Or just add them to New()
// Output:
// Output: "1234567"
// Output: "universe"
// Output: "world"
// POST JSON string
// POST Map, default is JSON content type. No need to set one
// POST Struct, default is JSON content type. No need to set one
// POST []byte array
// POST of raw bytes for file upload. For example: upload file to Dropbox
// Parsing public/private key pair from a pair of files. The files must contain PEM encoded data.
// Print with default helper functions
// Registering Request Middleware
// Registering Response Middleware
// Registering global Error object structure for JSON/XML request
// Registering in resty
// Request goes as JSON content type
// Result:
// Retries are configured per client
// Sample for creating certificate object
// Sample of using Request.SetQueryString method
// See we are not setting content-type header, since go-resty automatically detects Content-Type for you
// Set client timeout as per your need
// Set the previous transport that we created, set the scheme of the communication to the
// Setting a Proxy URL and Port
// Setting output directory path, If directory not exists then resty creates one!
// Should see the results
// Single file scenario
// TLS-ALPN challenge protocol to the NextProtos
// Target Host: example.com
// The correct way to manipulate the HTTP request using URL.Path as condition is:
// These are using the default foreground colors
// This is optional one, if you're planning using absolute path in
// This rejects the HTTPS request to *.reddit.com during HTTP CONNECT phase
// This will NOT reject the HTTPS request with URL ending with gif, due to the fact that proxy 
// To sort case-insensitive in French.
// To specify that numbers should sort numerically ("2" < "12")
// URL query parameters for all request
// Unique settings at Client level
// Use handy standard colors
// Use helper functions
// Use your own io.Writer output
// User Login
// User-Agent: ...
// Using raw func into resty.SetRedirectPolicy
// Using struct create more flexible redirect policy
// Wanna multiple policies such as redirect count, domain name check, etc
// Want to remove proxy setting
// Windows supported too! Just don't forget to change the output to color.Output
// You add one or more certificates
// You can mix up parameters
// You can override all below settings and options at request level if you want to
// You can pass you certificates through env variables as strings
// `Request.SetOutput` and can used together.
// accept a new connection
// alternatively, you can create a new viper instance.
// and use a comma to represent a decimal point.
// any approach to require this configuration into your program.
// application protocol after the TLS handshake, for example:
// be sure to customize NextProtos if serving a specific
// boolean or flags where the 'no option default value' is set
// configure the DNS provider (choose any from github.com/libdns)
// correctly populate the data.
// create records (AppendRecords is similar)
// delete records (this example uses provider-assigned ID)
// deprecate a flag by specifying its name and a usage message
// deprecate a flag shorthand by specifying its flag name and a usage message
// endpoints.go
// endpoints_test.go
// err = syscall.ENOENT
// err = syscall.EPERM
// error: open .env-is-not-exist: no such file or directory
// free up the muxing data
// gotenv.Env{"FOO": "bar"}
// gotenv.Env{"FOO": "test", "BAR": "test"}
// handler called after proxy receives HTTP Response from destination host, and before proxy forward 
// handler called after receiving HTTP CONNECT from the client, and before proxy establish connection 
// handler called before proxy send HTTP request to destination host
// hide a flag by specifying its name
// if the decision function returns an error, a certificate
// if you already have a TLS config you don't want to replace,
// if you don't have one, you should have disabled it earlier
// import "strings"
// it will throw a panic
// just mentioning about POST as an example with simple flow
// list records
// listen for connections to different domains
// look up the upstream host
// may not be obtained for that name at that time
// minimal example using Cloudflare
// mixed
// moduleConfig could be in a module specific package
// no matter which provider you use, the code stays the same!
// non-boolean and flags without a 'no option default value'
// only got the URL.Hostname and URL.Port during the HTTP CONNECT phase if the scheme is HTTPS, which is
// open a goroutine to watch remote changes forever
// or One can disable security check (https)
// or using an intermediate object
// panic: open .env-is-not-exist: no such file or directory
// parse out the HTTP request and the Host header
// provide an email address
// quiet common these days.
// read and agree to your CA's legal documents
// read from remote config the first time.
// retrieve data directly
// similarly user could do for XML too with -
// socket and set the unixSocket as the HostURL.
// start multiplexing on it
// the HTTP challenge has to be handled by your HTTP server;
// the Response to the client.
// this obtains certificates or renews them if necessary
// to use its certificates and solve the TLS-ALPN challenge,
// unmarshal config
// url.String() will be "http://news.example.com/articles/technology/42?filter=gorilla"
// use a query to gather elements without walking the tree
// use the staging endpoint while we're developing
// use this to configure a TLS listener
// vhostConn contains the entire request as if no bytes had been consumed
// vhostConn.ClientHelloMsg == nil (TLS)
// vhostConn.Host() == ""
// vhostConn.Request == nil (HTTP)
// we can simply set its GetCertificate field and append the
// when you made the certmagic.Config
// with destination host
// you can add one or more root certificates, its get appended
// you can get a TLS config to use in a TLS listener!
//--------------------------------
//---------------------------------------------------
//--------------------------------------------------------------------------------
//...
//// OR ////
0 or nil value for that type will be returned**.
0. ACME server (can be a publicly-trusted CA, or your own)
1. Ability to `Hijack` CONNECT requests. See
1. Construct the set of common code that is idential in all architecture-specific files.
1. Find, load, and unmarshal a configuration file in JSON, TOML, YAML, HCL, INI, envfile or Java properties formats.
1. Fork it
1. Public DNS name(s) you control
1. Ready to go out of the box. 
1. Replace all the println, printf, etc statements thoughout my code with
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2 clause BSD license. See [LICENSE](https://github.com/magiconair/properties/blob/master/LICENSE) file for details.
2. Allow the user to easily control what levels are printed to stdout
2. Create your feature branch (`git checkout -b my-new-feature`)
2. One library for both printing to the terminal and logging (to files).
2. Provide a mechanism to set default values for your different configuration options.
2. Server reachable from public Internet
2. Transparent proxy support for http/https including MITM certificate generation for TLS.  See the [transparent example.](https://github.com/elazarl/goproxy/tree/master/examples/goproxy-transparent)
2. Write this common code to the merged file.
2022/03/18 17:04:40 AMD Ryzen 9 3950X 16-Core Processor
2022/03/18 17:04:40 Microarchitecture level 3 is supported. Max level is 3.
2022/03/18 17:06:18 AMD Ryzen 9 3950X 16-Core Processor
2022/03/18 17:06:18 Microarchitecture level 4 not supported. Max level is 3.
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
3. Allow the user to easily control what levels are logged
3. Commit your changes (`git commit -am 'Add some feature'`)
3. Control over port 80 (HTTP) and/or 443 (HTTPS)
3. Provide a mechanism to set override values for options specified through command line flags.
3. Really easy to log to either a temp file or a file you specify.
3. Remove the common code from all architecture-specific files.
3: {"name":{"first":"Carol","last":"Anderson"},"age":52}
4. Persistent storage
4. Provide an alias system to easily rename parameters without breaking existing code.
4. Provide an easy mechanism (like fmt.Println) to print info to the user
4. Push to the branch (`git push origin my-new-feature`)
4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
5. Create new Pull Request
5. Due to 2 & 3 provide easy verbose mode for output and logs
5. Make it easy to tell the difference between when a user has provided a command line or config file which is the same as the default.
6. Not have any unnecessary initialization cruft. Just use it.
< 
< Access-Control-Allow-Methods: GET,PUT,PATCH,OPTIONS
< Access-Control-Allow-Origin: *
< Content-Length: 3
< Content-Type: text/plain; charset=utf-8
< Date: Fri, 28 Jun 2019 20:13:30 GMT
< HTTP/1.1 200 OK
</div>
</p>
<<FOO
<a href="SYNTAX.md"><img src="https://img.shields.io/badge/{}-syntax-33aa33.svg?style=flat-square" alt="GJSON Syntax"></a>
<a href="http://gocover.io/github.com/tidwall/buntdb"><img src="https://img.shields.io/badge/coverage-95%25-brightgreen.svg?style=flat-square" alt="Code Coverage"></a>
<a href="https://asciinema.org/a/32oseof9mkilg7t7d4780qt4m" target="_blank"><img src="https://asciinema.org/a/32oseof9mkilg7t7d4780qt4m.png" width="654"/></a>
<a href="https://godoc.org/github.com/tidwall/buntdb"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>
<a href="https://godoc.org/github.com/tidwall/gjson"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>
<a href="https://godoc.org/github.com/tidwall/tinyqueue"><img src="https://img.shields.io/badge/api-reference-blue.svg?style=flat-square" alt="GoDoc"></a>
<a href="https://goreportcard.com/report/github.com/tidwall/buntdb"><img src="https://goreportcard.com/badge/github.com/tidwall/buntdb?style=flat-square" alt="Go Report Card"></a>
<a href="https://opencollective.com/readline/backer/0/website" target="_blank"><img src="https://opencollective.com/readline/backer/0/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/1/website" target="_blank"><img src="https://opencollective.com/readline/backer/1/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/10/website" target="_blank"><img src="https://opencollective.com/readline/backer/10/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/11/website" target="_blank"><img src="https://opencollective.com/readline/backer/11/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/12/website" target="_blank"><img src="https://opencollective.com/readline/backer/12/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/13/website" target="_blank"><img src="https://opencollective.com/readline/backer/13/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/14/website" target="_blank"><img src="https://opencollective.com/readline/backer/14/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/15/website" target="_blank"><img src="https://opencollective.com/readline/backer/15/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/16/website" target="_blank"><img src="https://opencollective.com/readline/backer/16/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/17/website" target="_blank"><img src="https://opencollective.com/readline/backer/17/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/18/website" target="_blank"><img src="https://opencollective.com/readline/backer/18/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/19/website" target="_blank"><img src="https://opencollective.com/readline/backer/19/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/2/website" target="_blank"><img src="https://opencollective.com/readline/backer/2/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/20/website" target="_blank"><img src="https://opencollective.com/readline/backer/20/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/21/website" target="_blank"><img src="https://opencollective.com/readline/backer/21/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/22/website" target="_blank"><img src="https://opencollective.com/readline/backer/22/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/23/website" target="_blank"><img src="https://opencollective.com/readline/backer/23/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/24/website" target="_blank"><img src="https://opencollective.com/readline/backer/24/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/25/website" target="_blank"><img src="https://opencollective.com/readline/backer/25/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/26/website" target="_blank"><img src="https://opencollective.com/readline/backer/26/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/27/website" target="_blank"><img src="https://opencollective.com/readline/backer/27/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/28/website" target="_blank"><img src="https://opencollective.com/readline/backer/28/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/29/website" target="_blank"><img src="https://opencollective.com/readline/backer/29/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/3/website" target="_blank"><img src="https://opencollective.com/readline/backer/3/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/4/website" target="_blank"><img src="https://opencollective.com/readline/backer/4/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/5/website" target="_blank"><img src="https://opencollective.com/readline/backer/5/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/6/website" target="_blank"><img src="https://opencollective.com/readline/backer/6/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/7/website" target="_blank"><img src="https://opencollective.com/readline/backer/7/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/8/website" target="_blank"><img src="https://opencollective.com/readline/backer/8/avatar.svg"></a>
<a href="https://opencollective.com/readline/backer/9/website" target="_blank"><img src="https://opencollective.com/readline/backer/9/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/0/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/1/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/10/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/10/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/11/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/11/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/12/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/12/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/13/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/13/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/14/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/14/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/15/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/15/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/16/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/16/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/17/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/17/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/18/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/18/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/19/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/19/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/2/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/20/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/20/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/21/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/21/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/22/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/22/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/23/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/23/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/24/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/24/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/25/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/25/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/26/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/26/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/27/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/27/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/28/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/28/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/29/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/29/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/3/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/4/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/5/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/6/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/7/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/8/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/readline/sponsor/9/website" target="_blank"><img src="https://opencollective.com/readline/sponsor/9/avatar.svg"></a>
<a href="https://pkg.go.dev/github.com/libdns/libdns"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://tidwall.com/gjson-play"><img src="https://img.shields.io/badge/%F0%9F%8F%90-playground-9900cc.svg?style=flat-square" alt="GJSON Playground"></a>
<a href="https://travis-ci.org/tidwall/buntdb"><img src="https://img.shields.io/travis/tidwall/buntdb.svg?style=flat-square" alt="Build Status"></a>
<br>
<div align="center">
<h1 align="center">Resty</h1>
<h3 align="center">Easy and Powerful TLS Automation</h3>
<h4 align="center">Resty Communication Channels</h4>
<hr>
<img
<img 
<img src="https://raw.githubusercontent.com/chzyer/readline/assets/logo.png" />
<img src="https://raw.githubusercontent.com/chzyer/readline/assets/logo_f.png" />
<p align="center">
<p align="center"><a href="#features">Features</a> section describes in detail about Resty capabilities</p>
<p align="center"><a href="https://github.com/go-resty/resty/actions/workflows/ci.yml?query=branch%3Amaster"><img src="https://github.com/go-resty/resty/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a> <a href="https://codecov.io/gh/go-resty/resty/branch/master"><img src="https://codecov.io/gh/go-resty/resty/branch/master/graph/badge.svg" alt="Code Coverage"></a> <a href="https://goreportcard.com/report/go-resty/resty"><img src="https://goreportcard.com/badge/go-resty/resty" alt="Go Report Card"></a> <a href="https://github.com/go-resty/resty/releases/latest"><img src="https://img.shields.io/badge/version-2.12.0-blue.svg" alt="Release Version"></a> <a href="https://pkg.go.dev/github.com/go-resty/resty/v2"><img src="https://pkg.go.dev/badge/github.com/go-resty/resty" alt="GoDoc"></a> <a href="LICENSE"><img src="https://img.shields.io/github/license/go-resty/resty.svg" alt="License"></a> <a href="https://github.com/avelino/awesome-go"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome Go"></a></p>
<p align="center"><a href="https://gitter.im/go_resty/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge"><img src="https://badges.gitter.im/go_resty/community.svg" alt="Chat on Gitter - Resty Community"></a> <a href="https://twitter.com/go_resty"><img src="https://img.shields.io/badge/twitter-@go__resty-55acee.svg" alt="Twitter @go_resty"></a></p>
<p align="center">Simple HTTP and REST client library for Go (inspired by Ruby rest-client)</p>
<p align="center">The same library used by the <a href="https://caddyserver.com">Caddy Web Server</a></p>
<p align="center">get json values quickly</a></p>
<p>
<sup id="footnote-versions">1</sup> In particular, keep in mind that we may be
<sup>1. Not supported in multi-recipient mode</sup>
<sup>1. Only available in version 2 of the package</sup>
<sup>2. Only available in version 2 of the package</sup>
====
========
===============
=================
===========================
==================================
===========================================
===============================================
>
> 
> ## Viper v2 feedback
> **Thank you!**
> Accept: */*
> GET /foo HTTP/1.1
> Host: localhost:8080
> Less is more.
> User-Agent: curl/7.59.0
> Viper is heading towards v2 and we would love to hear what _**you**_ would like to see in it. Share your thoughts here: https://forms.gle/R6faU74qPRPAzchZ9
> WARNING: OctoDNS assumes ownership of any domain you point it to. When you tell it to act it will do whatever is necessary to try and match up states including deleting any unexpected records. Be careful when playing around with OctoDNS. 
> _Important_: there must be an `OPTIONS` method matcher for the middleware to set the headers.
>go run main.go
@pretty:{"sortKeys":true} 
A FileSystem Abstraction System for Go
A `-cpu.arm` flag for detecting unsafe ARM features can be added. See below.
A `DetectARM()` can be used if you are able to control your deployment,
A `net.Dialer` drop-in that establishes the TCP connection over an [HTTP CONNECT Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_tunneling).
A common question when viewing HCL is to ask the question: why not
A faster `cpuid.CPU.Has()` is provided which will usually be inlined by the gc compiler.  
A few different ways you could use Afero:
A few years later, Caddy's novel auto-HTTPS logic was extracted into a library called [CertMagic](https://github.com/caddyserver/certmagic) to be usable by any Go program. Caddy would continue to use CertMagic, which implemented the certificate _automation and management_ logic on top of the low-level certificate _obtain_ logic that lego provided.
A file containing Go types for passing into (or returning from) syscalls.
A file containing all of the system's generated error numbers, error strings,
A file containing all the generated syscalls for a specific GOOS and GOARCH.
A filtered view on file names, any file NOT matching
A frequently requested feature for Viper is adding more value formats and decoders.
A good configuration system will support default values. A default value is not
A key may contain special wildcard characters '\*' and '?'.
A list of numeric constants for all the syscall number of the specific GOOS
A modifier is a path component that performs custom processing on the 
A modifier may accept an optional argument. The argument can be a valid JSON 
A more complex authentication middleware, which maps session token to users, could be written as:
A not-so-up-to-date-list-that-may-be-actually-current:
A path is a series of keys separated by a dot.
A possible use case that suits goproxy but
A powerful readline library in `Linux` `macOS` `Windows` `Solaris`
A read-only base will make the overlay also read-only but still copy files
A read-only transaction should be used when you don't need to make changes to the data. The advantage of a read-only transaction is that there can be many running concurrently.
A read/write transaction is used when you need to make changes to your data. There can only be one read/write transaction running at a time. So make sure you close it as soon as you are done with it.
A short "how to use the API" is at the beginning of doc.go (this also will show when you call `godoc
A small examples section:
A thin wrapper around the source Fs providing a read only view.
A very basic middleware which logs the URI of the request being handled could be written as:
A: Viper is designed to be a [companion](http://en.wikipedia.org/wiki/Viper_(G.I._Joe))
ACMEz ("ack-measy" or "acme-zee", whichever you prefer) is a fully-compliant [RFC 8555](https://tools.ietf.org/html/rfc8555) (ACME) implementation in pure Go. It is lightweight, has an elegant Go API, and its retry logic is highly robust against external errors. ACMEz is suitable for large-scale enterprise deployments.
API documentation
API stability
APP_ID=1234567
APP_SECRET=abcdef
ASCEND_100: 2268998.79 operations per second
ASCEND_200: 1178388.14 operations per second
ASCEND_400: 679134.20 operations per second
ASCEND_800: 348445.55 operations per second
AddGoFlagSet().
Adding a new syscall often just requires adding a new `//sys` function prototype
Adding new syscall numbers is mostly done by running the build on a sufficiently
Additionally, CertMagic will retry failed validations with exponential backoff for up to 30 days, with a reasonable maximum interval between attempts (an "attempt" means trying each enabled challenge type once).
Afero also provides a fully atomic memory backed filesystem perfect for use in
Afero comes from the latin roots Ad-Facere.
Afero has experimental support for Google Cloud Storage (GCS). You can either set the
Afero has experimental support for secure file transfer protocol (sftp). Which can
Afero is a filesystem framework providing a simple, uniform and universal API
Afero is also a library providing a base set of interoperable backend
Afero is easy to use and easier to adopt.
Afero is released under the Apache 2.0 license. See
Afero provides a set of functions to make it easier to use the underlying file systems.
Afero provides an http compatible backend which can wrap any of the existing
Afero provides an httpFs file system which satisfies this requirement.
Afero provides significant improvements over using the os package alone, most
Afero provides the ability have two filesystems (or more) act as a single
After all flags are defined, call
After parsing, the arguments after the flag are available as the
After you create a flag it is possible to set the pflag.NoOptDefVal for
After you're done muxing, you probably don't need to inspect the header data anymore, so you can make it available for garbage collection:
Again, if you're needing to do this, you've probably over-complicated your application design.
Aliases permit a single value to be referenced by multiple keys
All APIs are finalized, and no breaking changes will be made in the 1.x series
All [releases](https://github.com/fsnotify/fsnotify/releases) are tagged based on [Semantic Versioning](http://semver.org/). Further API changes are [planned](https://github.com/fsnotify/fsnotify/milestones), and will be tagged with a new major revision number.
All keys/value pairs are ordered in the database by the key. To iterate over the keys:
All of the certificates in use are de-duplicated and cached in memory for optimal performance at handshake-time. This cache must be backed by persistent storage as described above.
All reads and writes must be performed from inside a transaction. BuntDB can have one write transaction opened at a time, but can have many concurrent read transactions. Each transaction maintains a stable view of the database. In other words, once a transaction has begun, the data for that transaction cannot be changed by other transactions.
All these high-level examples use `certmagic.Default` and `certmagic.DefaultACME` for the config and the default cache and storage for serving up certificates.
All variables defined in the route are required, and their values must conform to the corresponding patterns. These requirements guarantee that a generated URL will always match a registered route -- the only exception is for explicitly defined "build-only" routes which never match.
Along with `IndexString`, there is also `IndexInt`, `IndexUint`, and `IndexFloat`.
Also check out [SJSON](https://github.com/tidwall/sjson) for modifying json, and the [JJ](https://github.com/tidwall/jj) command line tool.
Alternatively, you can use `EnvKeyReplacer` with `NewWithOptions` factory function.
Although not strictly required, this is highly recommended best practice. It allows you to receive expiration emails if your certificates are expiring for some reason, and also allows the CA's engineers to potentially get in touch with you if something is wrong. I recommend setting `certmagic.DefaultACME.Email` or always setting the `Email` field of a new `Config` struct.
And an request to `/foo` using something like:
And if you use subrouters, host and path defined separately can be built as well:
And then add values:
And then you can run the `Intersects` function on the index:
And this is all you need to know about the basic usage. More advanced options are explained below.
Any Afero FileSystem can be used as an httpFs.
Any attempt to modify a file found only in the base will copy the file to the
Any index can be put in descending order by wrapping it's less function with `buntdb.Desc`.
AppFs.Open("/tmp/foo")
Arrays and Objects are returned as their raw json types. 
As a rule of the thumb, everything marked with safe won't overwrite any file, but just create if not existent, whilst the default behavior is to create or truncate.
As a workaround you'll need to delete keys following the completion of the iterator.
As measured by its own [benchmarking suite][], not only is zap more performant
As of now, yes. Looking into making this single-thread friendly (see [howeyc #7][#7])
As part of MemMapFs, Afero also provides an atomic, fully concurrent memory
As you may guess this log file can grow large over time.
At any rate, user feedback is very important for me, so I'll be delighted to know if you're using this package.
At time of writing (December 2018), Let's Encrypt only issues wildcard certificates with the DNS challenge. You can easily enable the DNS challenge with CertMagic for numerous providers (see the relevant section in the docs).
Authors
Available Loggers are:
BSD licensed. See the LICENSE file for details.
BTW, I'd like to know what you think about `Resty`. Kindly open an issue or send me an email; it'd mean a lot to me.
BTree implementation for Go
Because if you want to call [gRPC](http://www.grpc.io/) services which are exposed publicly over `:443` TLS over an HTTP proxy, you can't.
Because of this, we decided to create our own configuration language
Become a sponsor and get your logo here on our Github page. [[Become a sponsor](https://opencollective.com/readline#sponsor)]
Behind the scene, it will then load `.env` file and export the valid variables to the environment variables. Make sure you call the method as soon as possible to ensure it loads all variables, say, put it on `init()` function.
Below is a quick overview of the path syntax, for more complete information please
BenchmarkEasyJSONLexer-16            3000000       729 ns/op     501 B/op	       5 allocs/op
BenchmarkFFJSONLexer-16              1424979      2585 ns/op     880 B/op	       8 allocs/op
BenchmarkGJSONGet-16                11644512       311 ns/op       0 B/op	       0 allocs/op
BenchmarkGJSONUnmarshalMap-16        1122678      3094 ns/op    1920 B/op	      26 allocs/op
BenchmarkJSONCompact-16       685111    1699 ns/op    442 B/op     0 allocs/op
BenchmarkJSONDecoder-16               330450     10217 ns/op    3845 B/op	     160 allocs/op
BenchmarkJSONIndent-16        450654    2687 ns/op   1221 B/op     0 allocs/op
BenchmarkJSONIterator-16             3000000       869 ns/op     693 B/op	      14 allocs/op
BenchmarkJSONParserGet-16            3000000       366 ns/op      21 B/op	       0 allocs/op
BenchmarkJSONUnmarshalMap-16          516681      6810 ns/op    2944 B/op	      69 allocs/op
BenchmarkJSONUnmarshalStruct-16       697053      5400 ns/op     928 B/op	      13 allocs/op
BenchmarkPretty-16           1000000    1034 ns/op    720 B/op     2 allocs/op
BenchmarkPrettySortKeys-16    586797    1983 ns/op   2848 B/op    14 allocs/op
BenchmarkUgly-16             4652365     254 ns/op    240 B/op     1 allocs/op
BenchmarkUglyInPlace-16      6481233     183 ns/op      0 B/op     0 allocs/op
Benchmarks of GJSON alongside [encoding/json](https://golang.org/pkg/encoding/json/), 
Benchmarks of Pretty alongside the builtin `encoding/json` Indent/Compact methods.
Besides above functions, `gotenv` also provides another functions that overrides existing:
BindEnv("id")
Blazing fast, structured, leveled logging in Go.
Boolean flags (in their long form) accept 1, 0, t, f, true, false,
Boolean shorthand flags can be combined with other shorthand flags.
Both `gotenv.Load` and `gotenv.Apply` **DO NOT** overrides existing environment variables. If you want to override existing ones, you can see section below.
Both `gotenv.Load` and `gotenv.OverLoad` returns an error on something wrong occurred, like your env file is not exist, and so on. To make it easier to use, `gotenv` also provides `gotenv.Must` helper, to let it panic when an error returned.
BuntDB does not currently support deleting a key while in the process of iterating.
BuntDB has support for spatial indexes by storing rectangles in an [R-tree](https://en.wikipedia.org/wiki/R-tree). An R-tree is organized in a similar manner as a [B-tree](https://en.wikipedia.org/wiki/B-tree), and both are balanced trees. But, an R-tree is special because it can operate on data that is in multiple dimensions. This is super handy for Geospatial applications.
BuntDB is a low-level, in-memory, key/value store in pure Go.
BuntDB source code is available under the MIT [License](/LICENSE).
BuntDB uses an AOF (append-only file) which is a log of all database changes that occur from operations like `Set()` and `Delete()`.
By default BuntDB executes an `fsync` once every second on the [aof file](#append-only-file). Which simply means that there's a chance that up to one second of data might be lost. If you need higher durability then there's an optional database config setting `Config.SyncPolicy` which can be set to `Always`.
By default empty environment variables are considered unset and will fall back to
By default, CertMagic stores assets on the local file system in `$HOME/.local/share/certmagic` (and honors `$XDG_DATA_HOME` if set). CertMagic will create the directory if it does not exist. If writes are denied, things will not be happy, so make sure CertMagic can write to it!
By default, `gotenv.Load` will look for a file called `.env` in the current working directory.
By default, resty will retry requests that return a non-nil error during execution.
By setting this to a non-nil value, on-demand TLS is enabled for that config. For convenient security, CertMagic's high-level abstraction functions such as `HTTPS()`, `TLS()`, `ManageSync()`, `ManageAsync()`, and `Listen()` (which all accept a list of domain names) will whitelist those names automatically so only certificates for those names can be obtained when using the Default config. Usually this is sufficient for most users.
C library to parse and generate YAML data quickly and reliably.
CPU Family 23 Model: 113
CPU features are detected on startup, and kept for fast access through the life of the application.
Cache files in the layer for the given time.Duration, a cache duration of 0
Cacheline bytes: 64
Caddy is known for its robust HTTPS+ACME features. When ACME certificate authorities have had outages, in some cases Caddy was the only major client that didn't experience any downtime. Caddy can weather OCSP outages lasting days, or CA outages lasting weeks, without taking your sites offline.
Caddy was also the first to sport "on-demand" issuance technology, which obtains certificates during the first TLS handshake for an allowed SNI name.
Caddy's [automagic TLS features](https://caddyserver.com/docs/automatic-https)&mdash;now for your own Go programs&mdash;in one powerful and easy-to-use library!
Cast also provides identical methods To_____E. These return the same result as
Cast is a library to convert between different go types in a consistent and easy way.
Cast provides a handful of To_____ methods. These methods will always return
Cast provides simple functions to easily convert a number to a string, an
CertMagic - Automatic HTTPS using Let's Encrypt
CertMagic emits events when possible things of interest happen. Set the [`OnEvent` field of your `Config`](https://pkg.go.dev/github.com/caddyserver/certmagic#Config.OnEvent) to subscribe to events; ignore the ones you aren't interested in. Here are the events currently emitted along with their metadata you can use:
CertMagic is a project by [Matthew Holt](https://twitter.com/mholt6), who is the author; and various contributors, who are credited in the commit history of either CertMagic or Caddy.
CertMagic is licensed under Apache 2.0, an open source license. For convenience, its main points are summarized as follows (but this is no replacement for the actual license text):
CertMagic is the core of Caddy's advanced TLS automation code, extracted into a library. The underlying ACME client implementation is [ACMEz](https://github.com/mholt/acmez). CertMagic's code was originally a central part of Caddy even before Let's Encrypt entered public beta in 2015.
CertMagic is the most mature, robust, and powerful ACME client integration for Go... and perhaps ever.
CertMagic relies on storage to store certificates and other TLS assets (OCSP staple cache, coordinating locks, etc). Persistent storage is a requirement when using CertMagic: ephemeral storage will likely lead to rate limiting on the CA-side as CertMagic will always have to get new certificates.
CertMagic runs effectively behind load balancers and/or in cluster/fleet environments. In other words, you can have 10 or 1,000 servers all serving the same domain names, all sharing certificates and OCSP staples.
Changes to the file system will only be made in the overlay.
Check out the [collate project](https://github.com/tidwall/collate) for more information.
Chmod(name string, mode os.FileMode) : error
Choose as per your need.
Chown(name string, uid, gid int) : error
Chtimes(name string, atime time.Time, mtime time.Time) : error
Codes](http://en.wikipedia.org/wiki/ANSI_escape_code#Colors) in Go (Golang). It
Color lets you use colorized outputs in terms of [ANSI Escape
Color will colorize the json for outputing to the screen. 
Colorable writer for windows.
Comments and the order of keys are preserved. Comments can be modified
Compared to other ACME client libraries for Go, only CertMagic supports the full suite of ACME features, and no other library matches CertMagic's maturity and reliability.
Compatibility
Complete and usable DNS library. All Resource Records are supported, including the DNSSEC types.
Confirm that your value was set:
Consequently, CertMagic brings all these (and more) features and capabilities right into your own Go programs.
Create(name string) : File, error
Cross platform: Windows, Linux, BSD and macOS.
Currently `arm64/linux` and `arm64/freebsd` should be quite reliable. 
Currently x86 / x64 (AMD64/i386) and ARM (ARM64) is supported, and no external C (cgo) code is used, which should make the library very easy to use.
DESCEND_100: 2313821.69 operations per second
DESCEND_200: 1292738.38 operations per second
DESCEND_400: 675258.76 operations per second
DESCEND_800: 337481.67 operations per second
DNS Authors 2012-
Darwin 14 vs Darwin 15). This makes it easier to track the progress of changes
Default `Go` supports Proxy via environment variable `HTTP_PROXY`. Resty provides support via `SetProxy` & `RemoveProxy`.
Define flags using flag.String(), Bool(), Int(), etc.
Depending on what you want to manipulate, the ways to add handlers to each handler list are:
DirExists(path string) (bool, error)
Directories are not filtered.
Download as binary from: https://github.com/klauspost/cpuid/releases
Drop `v2` for others.
Duration flags accept any input valid for time.ParseDuration.
Each operation was rotated through one of the following search paths:
Easy and safe casting from one type to another in Go
Example
Example config:
Example programs can be found in the `github.com/miekg/exdns` repository.
Example:
Examples can be found in the Godoc
Examples:
Exists(path string) (bool, error)
Exit Code 0
Exit Code 1
FOO
Family 23 Model: 113 Vendor ID: AMD
Features
Features: ADX,AESNI,AVX,AVX2,BMI1,BMI2,CLMUL,CLZERO,CMOV,CMPXCHG8,CPBOOST,CX16,F16C,FMA3,FXSR,FXSROPT,HTT,HYPERVISOR,LAHF,LZCNT,MCAOVERFLOW,MMX,MMXEXT,MOVBE,NX,OSXSAVE,POPCNT,RDRAND,RDSEED,RDTSCP,SCE,SHA,SSE,SSE2,SSE3,SSE4,SSE42,SSE4A,SSSE3,SUCCOR,X87,XSAVE
Features: ADX,AESNI,AVX,AVX2,BMI1,BMI2,CLMUL,CMOV,CX16,F16C,FMA3,HTT,HYPERVISOR,LZCNT,MMX,MMXEXT,NX,POPCNT,RDRAND,RDSEED,RDTSCP,SHA,SSE,SSE2,SSE3,SSE4,SSE42,SSE4A,SSSE3
Feel free to report bugs and patches using GitHub's pull requests system on
Fiddler is an excellent software with similar intent. However, Fiddler is not
File Interfaces and Methods Available:
File System Methods Available:
FileContainsBytes(filename string, subslice []byte) (bool, error)
Files not matching the regexp provided will not be created.
Finally you can iterate over the index:
First define a package variable and set it to a pointer to a filesystem.
First use go get to install the latest version of the library.
First, our simple HTTP handler:
First, we'll follow best practices and do the following:
Flag parsing stops after the terminator "--". Unlike the flag package,
Flags may then be used directly. If you're using the flags themselves,
For a complete grammar, please see the parser itself. A high-level overview
For a complete list see [Afero's GoDoc](https://godoc.org/github.com/spf13/afero)
For applications that log in the hot path, reflection-based serialization and
For each OS, there is a hand-written Go file at `${GOOS}/types.go` (or
For example, all of these will return the same result:
For example, an application might use multiple different cache stores for different purposes:
For example, create a Consul key/value store key `MY_CONSUL_KEY` with value:
For example, given this configuration file, both `datastore.metric.host` and
For example, here we create a modifier that makes the entire json document upper
For example, if you're using the standard library:
For example, let's say we have several URLs that should only match when the host is `www.example.com`. Create a route for that host and get a "subrouter" from it:
For example, let's say you want to create an index for ordering names:
For example, most of logger packages doesn't show colors on windows. (I know we can do it with ansicon. But I don't want.)
For example, parsing character (dot, comma, semicolon, etc) separated strings into slices.
For example, the URL you should use as proxy when running `./bin/basic` is
For example, the `@pretty` modifier takes a json object as its argument. 
For example, to run all tests:
For example, using the built-in `@reverse` modifier on the above json document,
For example, you might have the following points (`[X Y M]` where XY is a point and M is a timestamp):
For example:
For fully-functional program examples, check out [this Twitter thread](https://twitter.com/mholt6/status/1073103805112147968) (or read it [unrolled into a single post](https://threadreaderapp.com/thread/1073103805112147968.html)). (Note that the package API has changed slightly since these posts.)
For incremental writes, you must provide the Rust version large enough buffers so that it can use vectorized instructions. This Go library performs consistently regardless of the size being sent into the update function.
For individual flags, the `BindPFlag()` method provides this functionality.
For macOS/Linux users, you can install via [brew](https://brew.sh/)
For more control (particularly, if you need a different way of managing each certificate), you'll make and use a `Cache` and a `Config` like so:
For such flags, the default value is just the initial value of the variable.
For that, a bunch of commands are available, each with its own purpose:
For this the `Flags()` command is provided.
For usage and examples see the [Godoc](http://godoc.org/github.com/mitchellh/mapstructure).
ForkExec wrapper. Unlike the first two, it does not call into the scheduler to
Frank
Frequency 0 hz
From there on the file is only appended.
Full programming languages such as Ruby enable complex behavior
GET: 4609604.74 operations per second
GIT_COMMITTER_DATE="$date" GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email" git tag -s -f ${tag} ${tag}^0 -m ${tag}
GJSON is a Go package that provides a [fast](#performance) and [simple](#get-a-value) way to get values from a json document.
GJSON supports the json types `string`, `number`, `bool`, and `null`. 
GOARCH are set correctly and run `mkall.sh`. This will generate the files for
GRECT
GRECT source code is available under the MIT [License](/LICENSE).
Generated by `mksyscall.go` (see above).
Generated by godefs and the types file (see above).
Get searches json for the specified path. A path is in dot syntax, such as "name.last" or "age". When the value is found it's returned immediately. 
Get the latest goproxy from `gopkg.in/elazarl/goproxy.v1`.
Get("/v1/users/{userId}/{subAccountId}/details")
GetInt("host.ports.1") // returns 6029
GetString("datastore.metric.host") // (returns "127.0.0.1")
GetString("datastore.metric.host") // returns "0.0.0.0"
GetTempDir(subPath string) string
Getting Started
Getting non-existent values will cause an `ErrNotFound` error.
Go 1.6 supports dependencies located in the `vendor/` folder. Unless you are creating a library, it is recommended that you copy fsnotify into `vendor/github.com/fsnotify/fsnotify` within your project, and likewise for `golang.org/x/sys`.
Go 1.8 introduced the ability to [gracefully shutdown](https://golang.org/doc/go1.8#http_shutdown) a `*http.Server`. Here's how to do that alongside `mux`:
Go library for the [TOML](https://toml.io/) format.
Go numeric constants. See `zsysnum_${GOOS}_${GOARCH}.go` for the generated
Go offers fantastic standard libraries for decoding formats such as JSON.
Go-toml follows [Semantic Versioning](http://semver.org/). The supported version
Go-toml provides the following features for using data parsed from TOML documents:
Go-toml provides three handy command line tools:
Gob, etc.) where you don't _quite_ know the structure of the underlying data
Gone are the days of needing to restart a server to have a config take effect,
Googles very well.
Grab it here:
Graphic by [JonnyEtc](http://jonnyetc.deviantart.com/art/And-That-s-Why-You-Always-Leave-a-Note-315311422)
Great! This example grants you much more flexibility for advanced programs. However, _the vast majority of you will only use the high-level functions described earlier_, especially since you can still customize them by setting the package-level `Default` config.
HCL (HashiCorp Configuration Language) is a configuration language built
HCL is also fully JSON compatible. That is, JSON can be used as completely
HCL is heavily inspired by
Hacker: true
Have a look on [Contributors](https://github.com/go-resty/resty/graphs/contributors) page.
Have a look on [Members](https://github.com/orgs/go-resty/people) page.
Have fun!
Here are some configuration options that can be use to change various behaviors of the database.
Here are some example [benchmarks](https://github.com/tidwall/raft-buntdb#raftstore-performance-comparison) when using BuntDB in a Raft Store implementation.
Here is an example of how to use Viper to search for and read a configuration file.
Here is an example of using `CORSMethodMiddleware` along with a custom `OPTIONS` handler to set all the required CORS headers:
Here we register three routes mapping URL paths to handlers. This is equivalent to how `http.HandleFunc()` works: if an incoming request URL matches one of the paths, the corresponding handler is called passing (`http.ResponseWriter`, `*http.Request`) as parameters.
Here's a complete, runnable example of a small `mux` based server:
Here's the example of this overrides behavior:
Here's the example of your app:
How fast is BuntDB?
How records are represented across providers varies widely, and each kind of record has different fields and semantics. In time, our goal is for the `libdns.Record` type to be able to represent most of them as concisely and simply as possible, with the interface methods able to deliver on most of the possible zone operations.
However, if `datastore.metric` was overridden (by a flag, an environment variable,
However, if you require advanced control over which domains can be issued certificates on-demand (for example, if you do not know which domain names you are managing, or just need to defer their operations until later), you should implement your own DecisionFunc:
However, it is much simpler to just decode this into a `map[string]interface{}`
However, you can find [a general-purpose dns-01 solver in CertMagic](https://pkg.go.dev/github.com/caddyserver/certmagic#DNS01Solver), which uses [libdns](https://github.com/libdns) packages to integrate with numerous DNS providers. You can use it like this:
I DO NOT offer support for providing or creating phishlets. I will also NOT help you with creation of your own phishlets. Please look for ready-to-use phishlets, provided by other people.
I am very much aware that Evilginx can be used for nefarious purposes. This work is merely a demonstration of what adept attackers can do. It is the defender's responsibility to take such attacks into consideration and find ways to protect their users against this type of phishing attacks. Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.
I apologize for the inconvenience.
I believe it is good enough for usage.
I have replaced all lightweight tags with signed tags using this script which should
I put the software temporarily under the Go-compatible BSD license.
I realized that all of the git tags I had pushed before v1.7.5 were lightweight tags
I really wanted a very straightforward library that could seamlessly do
I would welcome your contribution! If you find any improvement or issue you want to fix, feel free to send a pull request, I like pull requests that include test cases for fix/enhancement. I have done my best to bring pretty good code coverage. Feel free to write tests.
I wrote this for use in [hugo](https://gohugo.io). If you are looking
I'll change the import path.
I'll try to keep reasonable backwards compatibility. In case of a major API change,
I've received positive feedback from a few people who use goproxy in production settings.
If opened in a browser, the import path itself leads to the API documentation:
If the base filesystem is writeable, any changes to files will be
If the result is not a JSON array, the return value will be an array containing one result.
If the result represents a non-existent value, then an empty array will be returned.
If there was a response from the server, the original error will be wrapped in `*resty.ResponseError` which contains the last response received.
If this prevents someone from using the software, do let me know and I'll consider changing it.
If wrapping your handler is not a good solution, try this inside your `ServeHTTP()` instead:
If you are consuming JSON from an unpredictable source then you may want to validate prior to using GJSON.
If you are not running an HTTP server, you should disable the HTTP challenge _or_ run an HTTP server whose sole job it is to solve the HTTP challenge.
If you are running an HTTP server, solving this challenge is very easy: just wrap your handler in `HTTPChallengeHandler` _or_ call `SolveHTTPChallenge()` inside your own `ServeHTTP()` method.
If you are taking in data from YAML, TOML or JSON or other formats which lack
If you are using the `gjson.GetBytes(json, path)` function and you want to avoid converting `result.Raw` to a `[]byte`, then you can use this pattern:
If you are working with interfaces to handle things like dynamic content
If you have a pflag.FlagSet with a flag called 'flagname' of type int you
If you have any questions, please submit a github issue and any pull requests is welcomed :)
If you like, you can bind the flag to a variable using the Var() functions.
If you want everything about reverse proxy phishing with **Evilginx** - check out my [Evilginx Mastery](https://academy.breakdev.org/evilginx-mastery) course!
If you want to learn more about how to set it up, please follow the instructions in [this blog post](https://breakdev.org/evilginx-3-3-go-phish/)
If you want to learn more about reverse proxy phishing, I've published extensive blog posts about **Evilginx** here:
If you want to retry on errors encountered during the request, similar to the default behavior,
If you want to unmarshal configuration where the keys themselves contain dot (the default key delimiter),
If you write a Storage implementation, please add it to the [project wiki](https://github.com/caddyserver/certmagic/wiki/Storage-Implementations) so people can find it!
If you'd like to use Gophish to send out phishing links compatible with Evilginx, please use the official Gophish integration with Evilginx 3.3.
If you're implementing a tls-alpn-01 solver, the `acmez` package can help. It has the constant [`ACMETLS1Protocol`](https://pkg.go.dev/github.com/mholt/acmez#pkg-constants) which you can use to identify challenge handshakes by inspecting the ClientHello's ALPN extension. Simply complete the handshake using a certificate from the [`acmez.TLSALPN01ChallengeCert()`](https://pkg.go.dev/github.com/mholt/acmez#TLSALPN01ChallengeCert) function to solve the challenge.
If you're using the high-level convenience functions like `HTTPS()`, `Listen()`, or `TLS()`, the HTTP and/or TLS-ALPN challenges are solved for you because they also start listeners. However, if you're making a `Config` and you start your own server manually, you'll need to be sure the ACME challenges can be solved so certificates can be renewed.
If your JSON is contained in a `[]byte` slice, there's the [GetBytes](https://godoc.org/github.com/tidwall/gjson#GetBytes) function. This is preferred over `Get(string(data), path)`.
Implement [RedirectPolicy](redirect.go#L20) interface and register it with resty client. Have a look [redirect.go](redirect.go) for more information.
In 2014, the ISRG was finishing the development of its automated CA infrastructure: the first of its kind to become publicly-trusted, under the name Let's Encrypt, which used a young protocol called ACME to automate domain validation and certificate issuance.
In all of the examples above, they demonstrate using viper in its singleton
In case you want to learn how to install and use **Evilginx**, please refer to online documentation available at:
In contexts where performance is nice, but not critical, use the
In order to mock the http requests when testing your application you
In order to provide the best experience when using multiple sources, the decision has been made to make all keys case insensitive.
In order to refuse connections to reddit at work time
In order to support flags defined using Go's `flag` package, they must be added to the `pflag` flagset. This is usually necessary
In order to use goproxy, one should set their browser to use goproxy as an HTTP
In other words, the `acmez` package is **porcelain** while the `acme` package is **plumbing** (to use git's terminology).
In some applications it may make sense to define a new package that
In summary, the goal is that libdns providers can do what the above libraries/tools can do, but with more flexibility: they can create and delete TXT records for ACME challenges, they can replace entire zones, but they can also do incremental changes or simply read records.
In the case that our routes have [variables](#examples), we can pass those in the request. We could write
In the years since then, Caddy's TLS automation techniques have been widely adopted, tried and tested in production, and served millions of sites and secured trillions of connections.
In this case, both libraries are able to avoid a lot of data copying and will use vectorized instructions to hash as fast as possible, and perform similarly.
In this example all write operations will only occur in memory (MemMapFs)
In this example we are creating a multi value index on "name.last" and "age":
In your application this will be set to afero.NewOsFs() during testing you
Indexes can be created on individual fields inside JSON documents. BuntDB uses [GJSON](https://github.com/tidwall/gjson) under the hood.
Initially Resty started supporting `go modules` since `v1.10.0` release.
Initially all data is stored in a single [B-tree](https://en.wikipedia.org/wiki/B-tree) with each item having one key and one value. All of these items are ordered by the key. This is great for quickly getting a value from a key or [iterating](#iterating) over the keys. Feel free to peruse the [B-tree implementation](https://github.com/tidwall/btree).
Install by running:
Install from source:
Installation and usage
Installing binary:
Instead of:
Integer flags accept 1234, 0664, 0x1234 and may be negative.
Internally, the `NewCache` function can address `max-items` and `item-size` keys directly:
Introduction
Is there a better name for a [commander](http://en.wikipedia.org/wiki/Cobra_Commander)?
IsDir(path string) (bool, error)
IsEmpty(path string) (bool, error)
It also contains instructions on how to modify these files to add a new
It also has support for single color definitions (local). You can
It follows a lean and mean philosophy. If there is stuff you should know as a DNS programmer there
It has features such as [one line retrieval](#get-a-value), [dot notation paths](#path-syntax), [iteration](#iterate-through-an-object-or-array), and [parsing json lines](#json-lines).
It has support for 1-20 dimensions, and can store and search multidimensions interchangably in the same tree.
It is also possible to use `resty.Backoff(...)` to get arbitrary retry scenarios
It is important to note that if you repeat the composite literal you
It is instead to provide HCL as a specialized language for our tools,
It is possible to add flags that affects cpu detection.
It is possible to deprecate a flag, or just its shorthand. Deprecating a flag/shorthand hides it from help text and prints a usage message when the deprecated flag/shorthand is used.
It is possible to mark a flag as hidden, meaning it will still function as normal, however will not show up in usage/help text.
It is possible to set a custom flag name 'normalization function.' It allows flag names to be mutated both when created in the code and when used on the command line to some 'normalized' form. The 'normalized' form is used for comparison. Two examples of using the custom normalization func follow.
It is suitable for use in any situation where you would consider using the OS
It persists to disk, is ACID compliant, and uses locking for multiple
It supports reading from multiple files or URLs and Spring style recursive
It supports regular HTTP proxy, HTTPS through CONNECT, and "hijacking" HTTPS
It wouldn't be uncommon to have each test initialize a blank slate memory
It's also nice that unlike some of my other libraries (hugo, cobra, viper) it
It's also possible to open a database that does not persist to disk by using `:memory:` as the path of the file.
It's important to note that when you specify conditions using `AddRetryCondition`,
Items can be automatically evicted by using the `SetOptions` object in the `Set` function to set a `TTL`.
JSON Web Signature, and JSON Web Token standards.
JSON document used:
JSON encoder, and the base `Logger` strives to avoid serialization overhead
JSON fits a nice balance in this, but is fairly verbose and most
JSON instead of trying to generate HCL).
JSON, YAML, etc.?
JWW can log to any `io.Writer`:
JWW is primarily a wrapper around the excellent standard log library. It
Josh Baker [@tidwall](http://twitter.com/tidwall)
Just in case you want to parse environment variables from any `io.Reader`, gotenv keeps its `Parse` and `StrictParse` function as public API so you can use that.
K/V store. `crypt` defaults to etcd on http://127.0.0.1:4001.
Keep in mind that unmanaged certificates are (obviously) not renewed for you, so you'll have to replace them when you do. However, OCSP stapling is performed even for unmanaged certificates that qualify.
L1 Data Cache: 32768 bytes
L1 Instruction Cache: 32768 bytes
L2 Cache: 524288 bytes
L3 Cache: 16777216 bytes
Lastly, if there exists a key that matches the delimited key path, its value
Learn everything about the latest methods of phishing, using reverse proxying to bypass Multi-Factor Authentication. Learn to think like an attacker, during your red team engagements, and become the master of phishing with Evilginx.
Let's say you have `.env` file:
Let's start registering a couple of URL paths and handlers:
License
Like `BindEnv`, the value is not set when the binding method is called, but when
Likewise for TLS, you can look at detailed information about the ClientHello message:
Load environment variables dynamically in Go.
Log a message and 10 fields:
Log a message with a logger that already has 10 fields of context:
Log a static string, without any context or `printf`-style templating:
Logical Cores: 32
LogicalCores: 32
Love Readline? Help me keep it alive by donating funds to cover project expenses!<br />
MIT
Many Go projects are built using Viper including:
Match is a very simple pattern matcher where '*' matches on any 
Maybe you think that 7 levels are too much for any application... and you
Meanwhile, a project called [Caddy](https://caddyserver.com) was being developed which would be the first and only web server to use HTTPS _automatically and by default_. To make that possible, another project called lego was commissioned by the Caddy project to become of the first-ever ACME client libraries, and the first client written in Go. It was made by Sebastian Erhart (xenolf), and on day 1 of Let's Encrypt's public beta, Caddy used lego to obtain its first certificate automatically at startup, making Caddy and lego the first-ever integrated ACME client.
Microarchitecture level: 3
Middlewares are (typically) small pieces of code which take one request, do something with it, and pass it down to another middleware or the final handler. Some common use cases for middleware are request logging, header manipulation, or `ResponseWriter` hijacking.
Middlewares can be added to a router using `Router.Use()`:
Miek Gieben  -  2010-2012  -  <miek@miek.nl>
Mkdir(name string, perm os.FileMode) : error
MkdirAll(path string, perm os.FileMode) : error
Mksysnum is a Go program located at `${GOOS}/mksysnum.go` (or `mksysnum_${GOOS}.go`
More detailed example of mocking resty http requests using ginko could be found [here](https://github.com/jarcoal/httpmock#ginkgo--resty-example).
Most applications will not need to interact with certificate caches directly. Usually, the closest you will come is to set the package-wide `certmagic.Default.Storage` variable (before attempting to create any Configs) which defines how the cache is persisted. However, if your use case requires using different storage facilities for different Configs (that's highly unlikely and NOT recommended! Even Caddy doesn't get that crazy), you will need to call `certmagic.NewCache()` and pass in the storage you want to use, then get new `Config` structs with `certmagic.NewWithCache()` and pass in the cache.
Most code never instantiates this struct directly, and instead uses
Multiple paths can be "chained" together using the pipe character. 
Multiple retry conditions can be added.
Mux middlewares are defined using the de facto standard type:
Mux supports the addition of middlewares to a [Router](https://godoc.org/github.com/gorilla/mux#Router), which are executed in the order they are added if a match is found, including its subrouters.
NOTE: You can also use the library in a non-global setting by creating an instance of a Notebook:
Name() : string
Name: AMD Ryzen 9 3950X 16-Core Processor
Names in no particular order:
New features will be discussed on the [mailing list](https://groups.google.com/forum/#!forum/goproxy-dev)
New in version 1.2 is support for modifier functions and path chaining.
Next include Afero in your application.
No (it shouldn't be, unless you are watching where it was moved to).
No initialization or setup needs to happen. Just start calling things.
No, you must add watches for any directory you want to watch (a recursive watcher is on the roadmap [#18][]).
No, you will need to synchronize access to the viper yourself (for example by using the `sync` package). Concurrent reads and writes can cause a panic.
None of the specific paths are required, but at least one path should be provided
Normally, certificates are obtained and renewed before a listener starts serving, and then those certificates are maintained throughout the lifetime of the program. In other words, the certificate names are static. But sometimes you don't know all the names ahead of time, or you don't want to manage all the certificates up front. This is where On-Demand TLS shines.
Not all operating systems provide ARM features directly 
Note that JWW's own internal output uses log levels as well, so set the log
Note that Let's Encrypt imposes [strict rate limits](https://letsencrypt.org/docs/rate-limits/) at its production endpoint, so using it while developing your application may lock you out for a few days if you aren't careful!
Note that currently only features are detected on ARM, 
Note that for some cpu/os combinations some features will not be detected.
Note that hypervisors may not pass through all CPU features through to the guest OS,
Note that if multiple conditions are specified, a retry will occur if any of the conditions are met.
Note that the path provided to `PathPrefix()` represents a "wildcard": calling
Note that usage message is essential here, and it should not be empty.
Note that we returned nil value as the response. Had we returned a response, goproxy would
Note that zap only supports the two most recent minor versions of Go.
Note: The handler chain will be stopped if your middleware doesn't call `next.ServeHTTP()` with the corresponding parameters. This can be used to abort a request if the middleware writer wants to. Middlewares _should_ write to `ResponseWriter` if they _are_ going to terminate the request, and they _should not_ write to `ResponseWriter` if they _are not_ going to terminate it.
Now `mykey` will automatically be deleted after one second. You can remove the TTL by setting the value again with the same key/value, but with the options parameter set to nil.
Now let's see how to build registered URLs.
Now only items with keys that have the prefix `user:` will be added to the `names` index.
Now the DNS challenge will be used by default, and I can obtain certificates for wildcard domains, too. Enabling the DNS challenge disables the other challenges for that `certmagic.ACMEIssuer` instance.
Now you can add various names:
Now, CertMagic is _the actual library used by Caddy_. It's incredibly powerful and feature-rich, but also easy to use for simple Go programs: one line of code can enable fully-automated HTTPS applications with HTTP->HTTPS redirects.
Objects and nested objects are created using the structure shown below:
Of course, this has some obvious security implications. You don't want to DoS a CA or allow arbitrary clients to fill your storage with spammy TLS handshakes. That's why, when you enable On-Demand issuance, you should set limits or policy to allow getting certificates. CertMagic has an implicit whitelist built-in which is sufficient for nearly everyone, but also has a more advanced way to control on-demand issuance.
Of course, you're allowed to use `SecureRemoteProvider` also
On Linux, you can use `setcap` to grant your binary the permission to bind low ports:
Once loaded you can use `os.Getenv()` to get the value of the variable.
Once your flag implements this interface, you can simply tell Viper to bind it:
Once your flag set implements this interface, you can simply tell Viper to bind it:
One important thing to recognize is that each Get function will return a zero
One important thing to recognize when working with ENV variables is that the
One way to accomplish this is to define a variable as mentioned above.
Only master (`latest`) and tagged versions are published to dockerhub. You
Only the value is passed for arrays.
Open(name string) : File, error
OpenFile(name string, flag int, perm os.FileMode) : File, error
Optionally you can provide a function for Viper to run each time a change occurs.
Or download binaries from release page: https://github.com/klauspost/cpuid/releases
Or make two simple changes to an existing `tls.Config`:
Or use Unmarshal:
Or use a query:
Or you can create custom flags that satisfy the Value interface (with
Order by age
Order by age range 30-50
Order by last name
Originally invented for use in Caddy (which was the first program to use such technology), On-Demand TLS makes it possible and easy to serve certificates for arbitrary or specific names during the lifetime of the server. When a TLS handshake is received, CertMagic will read the Server Name Indication (SNI) value and either load and present that certificate in the ServerHello, or if one does not exist, it will obtain it from a CA right then-and-there.
OsFs it will still use the same underlying filesystem but will reduce
Our goal with HCL is not to alienate other configuration languages.
Our test code:
Our test file, with a table-driven test of `routeVariables`:
POSIX/GNU-style --flags.
Package `gorilla/mux` implements a request router and dispatcher for matching incoming requests to
Package cpuid provides information about the CPU running the current program.
Package goproxy provides a customizable HTTP proxy library for Go (golang),
Package home: https://github.com/klauspost/cpuid
Package ini provides INI file read and write functionality in Go.
Package jose aims to provide an implementation of the Javascript Object Signing
Password = "mypassword"`)
Paths can have variables. They are defined using the format `{name}` or `{name:pattern}`. If a regular expression pattern is not defined, the matched variable will be anything until the next slash. For example:
Per the ACME spec, the HTTP challenge requires port 80, or at least packet forwarding from port 80. It works by serving a specific HTTP response that only the genuine server would have to a normal HTTP request at a special endpoint.
Per the ACME spec, the TLS-ALPN challenge requires port 443, or at least packet forwarding from port 443. It works by providing a special certificate using a standard TLS extension, Application Layer Protocol Negotiation (ALPN), having a special value. This is the most convenient challenge type because it usually requires no extra configuration and uses the standard TLS port which is where the certificates are used, also.
Perhaps we can't populate a specific structure without first reading
PhysicalCores: 16
Please add `-u` flag to update in the future.
Please refer to [CONTRIBUTING][] before opening an issue or pull request.
Please see [Pretty Options](https://github.com/tidwall/pretty#customized-output) for more information.*
Please see [the documentation](https://godoc.org/github.com/fsnotify/fsnotify) and consult the [FAQ](#faq) for usage information.
Ported from the [tinyqueue](https://github.com/mourner/tinyqueue) Javascript library.
Porting Go to a new architecture/OS combination or adding syscalls, types, or
Present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.
Pretty is a Go package that provides [fast](#performance) methods for formatting JSON for human readability, or to compact JSON for smaller payloads.
Pretty source code is available under the MIT [License](/LICENSE).
Prichard
Prior to HCL, the tools we built at [HashiCorp](http://www.hashicorp.com)
Properties can be decoded into structs, maps, arrays and values through
Providers are 100% written and maintained by the community! We all maintain just the packages for providers we use.
Pure Go implementation of [BLAKE3](https://blake3.io) with AVX2 and SSE4.1 acceleration.
Put calls throughout your source based on type of feedback.
Put the gotenv package on your `import` statement:
Quickly get the outer rectangle for GeoJSON, WKT, WKB.
RTree implementation for Go
RTree source code is available under the MIT License.
Read a TOML document:
Read more about the details in [this blog post](https://sagikazarmark.hu/blog/decoding-custom-formats-with-viper/).
Read operations will first look in the overlay and if not found there, will
Read the full documentation on [![GoDoc](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](http://godoc.org/github.com/magiconair/properties)
ReadDir(dirname string) ([]os.FileInfo, error)
ReadFile(filename string) ([]byte, error)
Readdir(count int) : []os.FileInfo, error
Readdirnames(n int) : []string, error
Reading from config files is useful, but at times you want to store all modifications made at run time.
Realistically, libdns should enable most common record manipulations, but may not be able to fit absolutely 100% of all possibilities with DNS in a provider-agnostic way. That is probably OK; and given the wide varieties in DNS record types and provider APIs, it would be unreasonable to expect otherwise. We are not aiming for 100% fulfillment of 100% of users' requirements; more like 100% fulfillment of ~90% of users' requirements.
Recommended to use `go1.16` and above.
Redcon source code is available under the MIT [License](/LICENSE).
Regex support also exists for matching Headers within a route. For example, we could do:
Released under the [MIT License](LICENSE).
Released under the [MIT License].
Remember they only have to mean something to your project.
Remove(name string) : error
RemoveAll(path string) : error
Removing and Renaming files present only in the base layer is not currently
Rename(oldname, newname string) : error
Request Trace Info:
Requirements: bash, go
Requirements: bash, go, docker
Response Info:
Resty author also published following projects for Go Community.
Resty can be built, tested and depended upon via [Bazel](https://bazel.build).
Resty provides OnError hooks that may be called because:
Resty provides easy to use dynamic request URL path params. Params can be set at client and request level. Client level params value can be overridden at request level.
Resty provides few ready to use redirect policy(s) also it supports multiple policies together.
Resty provides middleware ability to manipulate for Request and Response. It is more flexible than callback approach.
Resty released under MIT license, refer [LICENSE](LICENSE) file.
Resty releases versions according to [Semantic Versioning](http://semver.org)
Resty uses [backoff](http://www.awsarchitectureblog.com/2015/03/backoff.html)
Results:
Returning `false` from an iterator will stop iteration.
Routes are tested in the order they were added to the router. If two routes match, the first one wins:
Routes can also be restricted to a domain or subdomain. Just define a host pattern to be matched. They can also have variables:
Routes can be named. All routes that define a name can have their URLs built, or "reversed". We define a name calling `Name()` on a route. For example:
Run tests by running:
SET: 248500.33 operations per second
SPATIAL_INTERSECTS_100: 939491.47 operations per second
SPATIAL_INTERSECTS_200: 561590.40 operations per second
SPATIAL_INTERSECTS_400: 306951.15 operations per second
SPATIAL_INTERSECTS_800: 159673.91 operations per second
SPATIAL_SET: 134824.60 operations per second
SafeWriteReader(path string, r io.Reader) (err error)
Sample output:
Seamless printing to the terminal (stdout) and logging to a io.Writer
See [Storage](#storage) and the associated [pkg.go.dev](https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc#Storage) for more information!
See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
See [example_test.go](https://github.com/fsnotify/fsnotify/blob/master/example_test.go).
See `types_darwin.go` and `linux/types.go` for examples.
See additional examples in the examples directory.
See below for a table of supported algorithms. Algorithm identifiers match
See below for a table of supported key types. These are understood by the
See https://godoc.org/github.com/cenkalti/backoff#pkg-examples
See the [Releases Page](https://github.com/spf13/afero/releases).
See the [`examples` folder](https://github.com/mholt/acmez/tree/master/examples) for tutorials on how to use either package. **Most users should follow the [porcelain guide](https://github.com/mholt/acmez/blob/master/examples/porcelain/main.go) to get started.**
See the [documentation][doc] and [FAQ](FAQ.md) for more details.
See the `crypt` documentation for examples of how to set encrypted values, or
Send pull request if you want to be listed here.
SetEnvPrefix("spf") // will be uppercased automatically
Setting the same matching conditions again and again can be boring, so we have a way to group several routes that share the same requirements. We call it "subrouting".
Shorthand letters can be used with single dashes on the command line.
Similarly, to configure ACME-specific defaults, use `certmagic.DefaultACME`.
Simply tell the viper instance to watchConfig.
Since then, Caddy has seen use in production longer than any other ACME client integration, and is well-known for being one of the most robust and reliable HTTPS implementations available today.
So if my application before had:
So instead of doing that let's pass a Viper instance to the constructor that represents a subset of the configuration:
So to create an index that is numerically ordered on an age key, we could use:
Some enterprises have fairly restrictive networking environments. They typically operate [HTTP forward proxies](https://en.wikipedia.org/wiki/Proxy_server) that require user authentication. These proxies usually allow  HTTPS (TCP to `:443`) to pass through the proxy using the [`CONNECT`](https://tools.ietf.org/html/rfc2616#section-9.9) method. The `CONNECT` method is basically a HTTP-negotiated "end-to-end" TCP stream... which is exactly what [`net.Conn`](https://golang.org/pkg/net/#Conn) is :)
Some known limitations of the existing implementation:
Sometimes you just want to know if a value exists. 
Soon thereafter, the lego project shifted maintainership and the goals and vision of the project diverged from those of Caddy's use case of managing tens of thousands of certificates per instance. Eventually, [the original Caddy author announced work on a new ACME client library in Go](https://github.com/caddyserver/certmagic/issues/71) that satisfied Caddy's harsh requirements for large-scale enterprise deployments, lean builds, and simple API. This work exceeded expectations and finally came to fruition in 2020 as ACMEz. It is much more lightweight with zero core dependencies, has a simple and elegant code base, and is thoroughly documented and easy to build upon.
Special thanks to the excellent [avo](https://github.com/mmcloughlin/avo) making writing vectorized version much easier.
Spotlight indexing on OS X can result in multiple events (see [howeyc #62][#62]). A temporary workaround is to add your folder(s) to the *Spotlight Privacy settings* until we have a native FSEvents implementation (see [#11][]).
Stable: No breaking changes will be made before 2.0.
Standard `go get`:
Starting Resty v2 and higher versions, it fully embraces [go modules](https://github.com/golang/go/wiki/Modules) package release. It requires a Go version capable of understanding `/vN` suffixed imports:
Starting from version 1.3.0 the behavior of the MustXXX() functions is
Stat() : os.FileInfo, error
Stat(name string) : os.FileInfo, error
States law, directive or regulation. In particular this software may not be
Subrouters can be used to create domain or path "namespaces": you define subrouters in a central place and then parts of the app can register its paths relatively to a given subrouter.
Suppose you want all the last names from the following json:
Sync() : error
Syria, Cuba, or North Korea, or to denied persons or entities mentioned on any
TRUE, FALSE, True, False.
Tables of supported algorithms are shown below. The library supports both
Technically all certificates these days are SAN certificates because CommonName is deprecated. But if you're asking whether CertMagic issues and manages certificates with multiple SANs, the answer is no. But it does support serving them, if you provide your own.
Technically, only one challenge needs to be enabled for things to work, but using multiple is good for reliability in case a challenge is discontinued by the CA. This happened to the TLS-SNI challenge in early 2018&mdash;many popular ACME clients such as Traefik and Autocert broke, resulting in downtime for some sites, until new releases were made and patches deployed, because they used only one challenge; Caddy, however&mdash;this library's forerunner&mdash;was unaffected because it also used the HTTP challenge. If multiple challenges are enabled, they are chosen randomly to help prevent false reliance on a single challenge type. And if one fails, any remaining enabled challenges are tried before giving up.
TempDir(dir, prefix string) (name string, err error)
TempFile(dir, prefix string) (f File, err error)
Testing handlers in a Go web application is straightforward, and _mux_ doesn't complicate this any further. Given two files: `endpoints.go` and `endpoints_test.go`, here's how we'd test an application using _mux_.
Thanks to:
That line of code will serve your HTTP router `mux` over HTTPS, complete with HTTP->HTTPS redirects. It obtains and renews the TLS certificates. It staples OCSP responses for greater privacy and security. As long as your domain name points to your server, CertMagic will keep its connections secure.
The BasePathFs restricts all operations to a given path within an Fs.
The CA may still enforce their own rate limits, and there's nothing (well, nothing ethical) CertMagic can do to bypass them for you.
The CacheOnReadFs will lazily make copies of any accessed files from the base
The CopyOnWriteFs is a read only base file system with a potentially
The DNS challenge is perhaps the most useful challenge because it allows you to obtain certificates without your server needing to be publicly accessible on the Internet, and it's the only challenge by which Let's Encrypt will issue wildcard certificates.
The English word that shares the same roots as Afero is "affair". Affair shares
The HTTP and TLS-ALPN challenges are the defaults because they don't require configuration from you, but they require that your server is accessible from external IPs on low ports. If that is not possible in your situation, you can enable the DNS challenge, which will disable the HTTP and TLS-ALPN challenges and use the DNS challenge exclusively.
The Http package requires a slightly specific version of Open which
The MIT License (MIT) + Apache 2.0. Read [LICENSE](LICENSE).
The MIT License (MIT) - see [`LICENSE.md`](https://github.com/fatih/color/blob/master/LICENSE.md) for more details
The OS specific files for the new build system are located in the `${GOOS}`
The [pkg.go.dev](https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc#OnDemandConfig) describes how to use this in full detail, so please check it out!
The `Config.SyncPolicy` has the following options:
The `Decode` function has examples associated with it there.
The `ForEachLines` function will iterate through JSON lines.
The `ForEach` function allows for quickly iterating through an object or array. 
The `Get*` and `Parse*` functions expects that the json is well-formed. Bad json will not panic, but it may return back unexpected results.
The `GetMany` function can be used to get multiple values at the same time.
The `Result` type holds one of these:
The `Walk` function on `mux.Router` can be used to visit all of the routes that are registered on a router. For example,
The `acmez` package is "bring-your-own-solver." It provides helper utilities for http-01, dns-01, and tls-alpn-01 challenges, but does not actually solve them for you. You must write or use an implementation of [`acmez.Solver`](https://pkg.go.dev/github.com/mholt/acmez#Solver) in order to get certificates. How this is done depends on your environment/situation.
The `certmagic.Config` struct is how you can wield the power of this fully armed and operational battle station. However, an empty/uninitialized `Config` is _not_ a valid one! In time, you will learn to use the force of `certmagic.NewDefault()` as I have.
The `color` package also disables color output if the [`NO_COLOR`](https://no-color.org) environment
The `cpuid.CPU` provides access to CPU features. Use `cpuid.CPU.Supports()` to check for CPU features.
The `result.Array()` function returns back an array of values.
The `result.Int()` and `result.Uint()` calls are capable of reading all 64 bits, allowing for large JSON integers.
The `result.Value()` function returns an `interface{}` which requires type assertion and is one of the following Go types:
The `syscall.go`, `syscall_${GOOS}.go`, `syscall_${GOOS}_${GOARCH}.go` are
The above example will make resty retry requests that end with a `429 Too Many Requests` status code.
The accessor methods also accept formatted paths to deeply nested keys. For
The afero utilities support all afero compatible backends.
The arguments are indexed from 0 through flag.NArg()-1.
The bracket syntax `[-117 30],[-112 36]` is unique to BuntDB, and it's how the built-in rectangles are processed. But, you are not limited to this syntax. Whatever Rect function you choose to use during `CreateSpatialIndex` will be used to process the parameter, in this case it's `IndexRect`.
The default Storage is implemented using the file system, so mounting the same shared folder is sufficient (see [Storage](#storage) for more on that)! If you need an alternate Storage implementation, feel free to use one, provided that all the instances use the _same_ one. :)
The default `Config` value is called `certmagic.Default`. Change its fields to suit your needs, then call `certmagic.NewDefault()` when you need a valid `Config` value. In other words, `certmagic.Default` is a template and is not valid for use directly.
The default set of command-line flags is controlled by
The documentation and additional examples are available at
The dot and wildcard characters can be escaped with '\\'.
The downside of internal buffering is most apparent with small sizes as most time is spent initializing the hasher state. In terms of hashing rate, the difference is 3-4x, but in an absolute sense it's ~100ns (see tables below). If you wish to hash a large number of very small strings and you care about those nanoseconds, be sure to use the Reset method to avoid re-initializing the state.
The easiest way to change the storage being used is to set `certmagic.Default.Storage` to a value that satisfies the [Storage interface](https://pkg.go.dev/github.com/caddyserver/certmagic?tab=doc#Storage). Keep in mind that a valid `Storage` must be able to implement some operations atomically in order to provide locking and synchronization.
The entire HTTP request headers are available for inspection in case you want to mux on something besides the Host header:
The error numbers and strings are generated from `#include <errno.h>`, and the
The first and second are the standard ones; they differ only in how many
The first is simply a wrapper around the native OS calls. This makes it
The following changes were made:
The following code:
The following examples are merely a sample of what is available. Please review
The following functions and methods exist:
The following is a short list of possible backends we hope someone will
The following samples will assist you to become as comfortable as possible with resty library.
The format of this file looks like:
The given file name to the operations on this Fs will be prepended with
The gotenv package is a Go port of [`dotenv`](https://github.com/bkeepers/dotenv) project with some additions made for Go. For general features, it aims to be compatible as close as possible.
The hand-written assembly file at `asm_${GOOS}_${GOARCH}.s` implements system
The hardest part about preparing this file is figuring out which headers to
The high-level functions in this package (`HTTPS()`, `Listen()`, `ManageSync()`, and `ManageAsync()`) use the default config exclusively. This is how most of you will interact with the package. This is suitable when all your certificates are managed the same way. However, if you need to manage certificates differently depending on their name, you will need to make your own cache and configs (keep reading).
The implementation follows the
The import path for the package is *gopkg.in/yaml.v2*.
The intent of the proxy is to be usable with reasonable amount of traffic,
The interfaces include:
The key and value are passed to the iterator function for objects.
The list of utilities includes:
The literal meaning of afero is "to make" or "to do" which seems very fitting
The lower-level go-vhost interface are just functions which extract the name/routing information for the given protocol and return an object implementing net.Conn which works as if no bytes had been consumed.
The merge is performed in the following steps:
The minimum requirement of Go is **1.12**.
The mksyscall.go program takes the `//sys` and `//sysnb` comments and converts
The name mux stands for "HTTP request multiplexer". Like the standard `http.ServeMux`, `mux.Router` matches incoming requests against a list of registered routes and calls a handler for the route that matches the URL or other conditions. The main features are:
The names are used to create a map of route variables which can be retrieved calling `mux.Vars()`:
The new build system uses a Docker container to generate the go files directly
The next version of go-toml is in [active development][v2-dev], and
The notion of a "cluster" or "fleet" of instances that may be serving the same site and sharing certificates, etc, is tied to storage. Simply, any instances that use the same storage facilities are considered part of the cluster. So if you deploy 100 instances of CertMagic behind a load balancer, they are all part of the same cluster if they share the same storage configuration. Sharing storage could be mounting a shared folder, or implementing some other distributed storage system such as a database server or KV store.
The old `v1` branch ([go-jose.v1](https://gopkg.in/square/go-jose.v1)) will
The old build system generates the Go files based on the C header files
The output should be:
The package API for yaml v2 will remain stable as described in [gopkg.in](https://gopkg.in).
The pattern parameter can be used to filter on keys like this:
The pflag package also defines some new functions that are not in flag,
The primary object in BuntDB is a `DB`. To open or create your
The properties library supports both ISO-8859-1 and UTF-8 encoded data.
The proxy itself is simply a `net/http` handler.
The remaining features (Document structure editing and tooling) will be added
The resulting code is easy to test, since it's decoupled from the main config structure,
The retries exponentially increase and stop increasing when a certain threshold is met.
The return value is a `[]Result`, which will always contain exactly the same number of items as the input paths.
The script `./fuzz.sh` is available to
The second param is used for a customizing the style, and passing nil will use the default `pretty.TerminalStyle`.
The shrink operation does not lock up the database so read and write transactions can continue while shrinking is in process.
The simplest way to enable on-demand issuance is to set the OnDemand field of a Config (or the default package-level value):
The speed caps out at around 1 kib, so most rows have been elided from the presentation.
The standard method is to have a struct pre-created, and populate that struct
The sys/unix package provides access to the raw system call interface of the
The three URL paths we registered above will only be tested if the domain is `www.example.com`, because the subrouter is tested first. This is not only convenient, but also optimizes request matching. You can create subrouters combining any attribute matchers accepted by a route.
The threshold can be changed at any time, but will only affect calls that
The use of [pflag](https://github.com/spf13/pflag/) in Viper does not preclude
The yaml package enables Go programs to comfortably encode and decode YAML
The yaml package is licensed under the Apache License 2.0. Please see the LICENSE file for details.
The yaml package supports most of YAML 1.1 and 1.2, including support for
Then `IndexRect` is a built-in function that converts rect strings to a format that the R-tree can use. It's easy to use this function out of the box, but you might find it better to create a custom one that renders from a different format, such as [Well-known text](https://en.wikipedia.org/wiki/Well-known_text) or [GeoJSON](http://geojson.org/).
Then in my tests I would initialize a new MemMapFs for each test:
Then just make sure your TLS listener is listening on port 443:
Then register routes in the subrouter:
Then, edit the regex (if necessary) to match the desired constant. Avoid making
There are 3 kinds of useful handlers to manipulate the behavior, as follows:
There are OS-specific limits as to how many watches can be created:
There are a variety of handy functions that work on a result:
There are currently the following built-in modifiers:
There are currently two ways we generate the necessary files. We are currently
There are helper functions available to get the value stored in a Flag if you have a FlagSet but find
There are many ways to use this library. We'll start with the highest-level (simplest) and work down (more control).
There are ongoing discussions about making that optional.
There are several other matchers that can be added. To match path prefixes:
There are two methods to do this:
There has been several attempts to implement case sensitivity, but unfortunately it's not that trivial. We might take a stab at implementing it in [Viper v2](https://github.com/spf13/viper/issues/772), but despite the initial noise, it does not seem to be requested that much.
There is a large benefit to using a mock filesystem for testing. It has a
There is also `AscendGreaterOrEqual`, `AscendLessThan`, `AscendRange`, `AscendEqual`, `Descend`, `DescendLessOrEqual`, `DescendGreaterThan`, `DescendRange`, and `DescendEqual`. Please see the [documentation](https://godoc.org/github.com/tidwall/buntdb) for more information on these functions.
There is also a `Shrink()` function which will rewrite the aof file so that it contains only the items in the database.
There is one exception to this: if you directly instantiate the Flag struct
There might be a case where you want to explicitly disable/enable color output. the 
There's a [custom utility](https://github.com/tidwall/buntdb-benchmark) that was created specifically for benchmarking BuntDB.
There's a `Parse(json)` function that will do a simple parse, and `result.Get(path)` that will search a result.
There's a `PrettyOptions(json, opts)` function which allows for customizing the output with the following options:
There's a background routine that automatically shrinks the log file when it gets too large.
There's also a way to build only the URL host or path for a route: use the methods `URLHost()` or `URLPath()` instead. For the previous route, we would do:
There's also support for Collation on JSON indexes:
There's one more thing about subroutes. When a subrouter has a path prefix, the inner routes use it as base for their paths:
There's support for [JSON Lines](http://jsonlines.org/) using the `..` prefix, which treats a multilined document as an array. 
Therefore, the above setup will result in resty retrying requests with non-nil errors up to 3 times,
These are built-in types for indexing. You can choose to use these or create your own.
These could be from a command line flag, or from your own application logic.
These each are loggers based on the log standard library and follow the
These functions have been primarily ported from io & ioutil with some developed for Hugo.
They are available under two different approaches to use. You can either call
They must be called from within the docker container.
This README is a quick overview of how to use GJSON, for more information check out [GJSON Syntax](SYNTAX.md).
This also works for host and query value variables:
This can be using with `cpuid.CPU.HasAll(f)` to quickly test if all features are supported.
This challenge is easy to solve: just use the provided `tls.Config` when you make your TLS listener:
This challenge works by setting a special record in the domain's zone. To do this automatically, your DNS provider needs to offer an API by which changes can be made to domain names, and the changes need to take effect immediately for best results. CertMagic supports [all DNS providers with `libdns` implementations](https://github.com/libdns)! It always cleans up the temporary record after the challenge completes.
This code is published under an MIT license. See LICENSE file for more information.
This declares an integer flag, -flagname, stored in the pointer ip, with type *int.
This example will generate the following output:
This hides "badflag" from help text, and prints `Flag --badflag has been deprecated, please use --good-flag instead` when "badflag" is used.
This hides the shortname "n" from help text, and prints `Flag shorthand -n has been deprecated, please use --noshorthandflag only` when the shorthand "n" is used.
This is a Go port of the exponential backoff algorithm from [Google's HTTP Client Library for Java][google-http-java-client].
This is a best-effort no allocation sub slice of the original json. This method utilizes the `result.Index` field, which is the position of the raw data in the original json. It's possible that the value of `result.Index` equals zero, in which case the `result.Raw` is converted to a `[]byte`.
This is a fork of the wonderful [google/btree](https://github.com/google/btree) package. It's has all the same great features and adds a few more.
This is a great new feature that allows for entering the same item into multiple B-trees, and each B-tree have a different ordering formula.
This is already available in Viper using mapstructure decode hooks.
This is being done on an OS-by-OS basis. Please update this documentation as
This is incredibly useful when you are maintaining your own zone file, but risky when you just need incremental changes.
This is similar to a [multi column index](http://dev.mysql.com/doc/refman/5.7/en/multiple-column-indexes.html) in a traditional SQL database.
This is to avoid differences in interpretation of messages between go-jose and
This is useful for getting results from a modified query.
This is very useful if your application has a verbose mode. Of course you
This library is most useful when decoding values from some data stream (JSON,
This library makes some different design decisions than the upstream Rust crate around internal buffering. Specifically, because it does not target the embedded system space, nor does it support multithreading, it elects to do its own internal buffering. This means that a user does not have to worry about providing large enough buffers to get the best possible performance, but it does worse on smaller input sizes. So some notes:
This library supports TOML version
This library uses Go modules and uses semantic versioning. Building is done with the `go` tool, so
This library uses Let's Encrypt by default, but you can use any certificate authority that conforms to the ACME specification. Known/common CAs are provided as consts in the package, for example `LetsEncryptStagingCA` and `LetsEncryptProductionCA`.
This line will add `X-GoProxy: yxorPoG-X` header to all requests sent through the proxy
This means that any detection used in `init()` functions will not contain these flags.
This module has two primary packages:
This must be called *before* `flag.Parse()` AND after the flags have been parsed `Detect()` must be called.
This obeys the precedence rules established above; the search for the path
This package is possible to handle escape sequence for ansi color on windows.
This package provides an in-memory B-Tree implementation for Go, useful as
This package provides an in-memory R-Tree implementation for Go, useful as a spatial data structure.
This program is used to extract duplicate const, func, and type declarations
This project is under Apache v2 License. See the [LICENSE](LICENSE) file for the full license text.
This read process happens one time when the database opens.
This repository contains a fork of the `encoding/json` package from Go 1.6.
This repository defines the core interfaces that provider packages should implement. They are small and idiomatic Go interfaces with well-defined semantics.
This script is used to generate the system's various constants. This doesn't
This section describes how to solve the ACME challenges. Challenges are how you demonstrate to the certificate authority some control over your domain name, thus authorizing them to grant you a certificate for that name. [The great innovation of ACME](https://www.dotconferences.com/2016/10/matthew-holt-go-with-acme) is that verification by CAs can now be automated, rather than having to click links in emails (who ever thought that was a good idea??).
This section describes the various files used in the code generation process.
This starts HTTP and HTTPS listeners and redirects HTTP to HTTPS!
This tool is a successor to [Evilginx](https://github.com/kgretzky/evilginx), released in 2017, which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website.
This will create a multi value index where the last name is ascending and the age is descending.
This will create an index named `names` which stores and sorts all values. The second parameter is a pattern that is used to filter on keys. A `*` wildcard argument means that we want to accept all keys. `IndexString` is a built-in function that performs case-insensitive ordering on the values
This will get all three positions.
This will print:
This will retrieve the library.
This would be equivalent to the following json:
Those tools are also available as a Docker image from
Though technically in beta, v2 is already more tested, [fixes bugs][v1-bugs],
Threads Per Core: 2
ThreadsPerCore: 2
Throughout your application use any function and method like you normally
To access an array value use the index as the key.
To add a constant, add the header that includes it to the appropriate variable.
To add a new type, add in the necessary include statement at the top of the
To add some lon,lat points to the `fleet` index:
To avoid firehosing the CA's servers, CertMagic has built-in rate limiting. Currently, its default limit is up to 10 transactions (obtain or renew) every 1 minute (sliding window). This can be changed by setting the `RateLimitEvents` and `RateLimitEventsWindow` variables, if desired.
To avoid this, if you are using the old build system, only generate the Go
To build a URL, get the route and call the `URL()` method, passing a sequence of key/value pairs for the route variables. For the previous route, we would do:
To build all the files under the new build system, you must be on an amd64/Linux
To build the files for your current OS and architecture, make sure GOOS and
To create a spatial index use the `CreateSpatialIndex` function:
To directly access the value:
To do so, simply ensure that each instance is using the same Storage. That is the sole criteria for determining whether an instance is part of a cluster.
To enable it, just set the `DNS01Solver` field on a `certmagic.ACMEIssuer` struct, or set the default `certmagic.ACMEIssuer.DNS01Solver` variable. For example, if my domains' DNS was served by Cloudflare:
To enable remote support in Viper, do a blank import of the `viper/remote`
To get a taste of `goproxy`, a basic HTTP/HTTPS transparent proxy
To get the number of elements in an array or to access a child path, use the '#' character.
To get the value:
To install it, run:
To install this utility:
To install:
To modify your app environment variables, `gotenv` expose 2 main functions:
To output color in GitHub Actions (or other CI systems that support ANSI colors), make sure to set `color.NoColor = false` so that it bypasses the check for non-tty output streams. 
To set a value you must open a read/write transaction:
To start using BuntDB, install Go and run `go get`:
To start using GJSON, install Go and run `go get`:
To start using Pretty, install Go and run `go get`:
To test a larger number of features, they can be combined using `f := CombineFeatures(CMOV, CMPXCHG8, X87, FXSR, MMX, SYSCALL, SSE, SSE2)`, etc.
To unmarshal to a `map[string]interface{}`:
To update the configuration you should call `ReadConfig` followed by `SetConfig`. For example:
To use staging, set `certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA` or set `CA` of every `ACMEIssuer` struct.
To work with DNS records managed by Cloudflare, for example, we can use [libdns/cloudflare](https://pkg.go.dev/github.com/libdns/cloudflare):
To writing files to the overlay only, you can use the overlay Fs directly (not
Transactions run in a function that exposes a `Tx` object, which represents the transaction state. While inside a transaction, all database operations should be performed using this object. You should never access the origin `DB` object while inside a transaction. Doing so may have side-effects, such as blocking your application.
Truncate(size int64) : error
Typically, the returned handler is a closure which does something with the http.ResponseWriter and http.Request passed to it, and then calls the handler passed as parameter to the MiddlewareFunc. This takes advantage of closures being able access variables from the context where they are created, while retaining the signature enforced by the receivers.
US maintained blocked list.
Under the default thresholds :
Unlike `SetEnvKeyReplacer`, it accepts a `StringReplacer` interface allowing you to write custom string replacing logic.
Unlike the flag package, a single dash before an option means something
Usage example:
Use CertMagic:
Use the `Nearby` function to get all the positions in order of nearest to farthest :
User = "pelletier"
User could register choice of JSON/XML library into resty or write your own. By default resty registers standard `encoding/json` and `encoding/xml` respectively.
User defined context
Using the external [collate package](https://github.com/tidwall/collate) it's possible to create
Using this example:
Value expressions can refer to other keys like in `${key}` or to environment
Vendor ID: AMD
Vendor String: AuthenticAMD
Viper also supports unmarshaling into embedded structs:
Viper can access a nested field by passing a `.` delimited path of keys:
Viper can access array indices by using numbers in the path. For example:
Viper can be thought of as a registry for all of your applications configuration needs.
Viper comes ready to use out of the box. There is no configuration or
Viper does not default to any configuration search paths leaving defaults decision
Viper does the following for you:
Viper has full support for environment variables. This enables 12 factor
Viper has the ability to bind to flags. Specifically, Viper supports `Pflags`
Viper is a complete configuration solution for Go applications including 12-Factor apps. It is designed
Viper is here to help with that.
Viper merges configuration from various sources, many of which are either case insensitive or uses different casing than the rest of the sources (eg. env vars).
Viper predefines many configuration sources such as files, environment
Viper provides a mechanism to try to ensure that ENV variables are unique. By
Viper requires minimal configuration so it knows where to look for config files.
Viper supports JSON, TOML, YAML, HCL, INI, envfile and Java Properties files. Viper can search multiple paths, but
Viper supports the ability to have your application live read a config file while running.
Viper uses [crypt](https://github.com/bketelsen/crypt) to retrieve
Viper uses [github.com/mitchellh/mapstructure](https://github.com/mitchellh/mapstructure) under the hood for unmarshaling values which uses `mapstructure` tags by default.
Viper uses the following precedence order. Each item takes precedence over the item below it:
Viper will automatically assume that the ENV variable matches the following format: prefix + "_" + the key name in ALL CAPS. When you explicitly provide the ENV variable name (the second parameter),
Viper will look for the ENV variable "ID".
Viper will read a config string (as JSON, TOML, YAML, HCL or envfile) retrieved from a path
Walk(root string, walkFn filepath.WalkFunc) error
We could pass the cache name to a module (eg. `NewCache("cache1")`),
We encourage and support an active, healthy community of contributors &mdash;
We have Streaming SIMD 2 Extensions
We try to keep the "master" branch as sane as possible and at the bleeding edge of standards,
We use [gopkg.in](https://gopkg.in) for versioning.
We welcome your contributions! Please see our **[contributing guidelines](https://github.com/caddyserver/certmagic/blob/master/.github/CONTRIBUTING.md)** for instructions.
We will only process requests that match the condition. `DstHostIs("www.reddit.com")` will return
We would replace it with:
When a transaction fails, it will roll back, and revert all changes that occurred to the database during that transaction. There's a single return value that you can use to close the transaction. For read/write transactions, returning an error this way will force the transaction to roll back. When a read/write transaction succeeds all changes are persisted to disk.
When developing reusable modules, it's often useful to extract a subset of the configuration
When performance and type safety are critical, use the `Logger`. It's even
When porting Go to a new architecture/OS, this file must be implemented for
When the database opens again, it will read back the aof file and process each command in exact order.
When using the default resty client, you should pass the client to the library as follow:
When working with dynamic data in Go you often need to cast or convert the data
When working with multiple vipers, it is up to the user to keep track of the
Which makes the json pretty and orders all of its keys.
Which will return:
While `gotenv.Load` loads entries from `.env` file, `gotenv.Apply` allows you to use any `io.Reader`:
While developing your application and testing it, use [their staging endpoint](https://letsencrypt.org/docs/staging-environment/) which has much higher rate limits. Even then, don't hammer it: but it's much safer for when you're testing. When deploying, though, use their production CA because their staging CA doesn't issue trusted certificates.
Will add color to the result for printing to the terminal.
Will format the json to:
With BuntDB it's possible to join multiple values on a single index.
With CertMagic, you can add one line to your Go application to serve securely over TLS, without ever having to touch certificates.
With a [correctly configured](https://golang.org/doc/install#testing) Go toolchain:
With goproxy you could ask all your users to set their proxy to a dedicated machine running a
Worst case you have to reclone the repo.
Would look like:
Would result in something like
WriteFile(filename string, data []byte, perm os.FileMode) error
WriteReader(path string, r io.Reader) (err error)
WriteString(s string) : ret int, err error
Yasuhiro Matsumoto (a.k.a mattn)
Yes, just call the relevant method on the `Config` to add your own certificate to the cache:
You also have the option of Unmarshaling all or a specific value to a struct, map,
You can [watch a 2016 dotGo talk](https://www.dotconferences.com/2016/10/matthew-holt-go-with-acme) by the author of this library about using ACME to automate certificate management in Go programs:
You can access the CPU information by accessing the shared CPU variable of the cpuid library.
You can also add custom modifiers.
You can also bind an existing set of pflags (pflag.FlagSet):
You can also create custom indexes that allow for ordering and [iterating](#iterating) over values. A custom index also uses a B-tree, but it's more flexible because it allows for custom ordering.
You can also create many different vipers for use in your application. Each will
You can also load other than `.env` file if you wish. Just supply filenames when calling `Load()`. It will load them in order and the first value set for a variable will win.:
You can also query an array for the first match by using `#(...)`, or find all 
You can also query an object inside an array:
You can also represent `Infinity` by using `-inf` and `+inf`.
You can also run the standard Go benchmark tool from the project root directory:
You can compile above code on non-windows OSs.
You can find the custom version here in the forked repository: [Gophish with Evilginx integration](https://github.com/kgretzky/gophish/)
You can handle the specific case where no config file is found like this:
You can optionally provide client with [custom retry conditions](https://pkg.go.dev/github.com/go-resty/resty/v2#RetryConditionFunc):
You can see the full reference documentation of the pflag package
You can set the default values easily, for example: `certmagic.Default.Issuer = ...`.
You can then do a search for all points with `M` between 2-4 by calling `Intersects`.
You can use remote configuration in conjunction with local configuration, or
You can use various combinations of `PATCH` method call like demonstrated for `POST`.
You can use various combinations of `PUT` method call like demonstrated for `POST`.
You can use your favorite format's marshaller with the config returned by `AllSettings()`.
You can vote for case sensitivity by filling out this feedback form: https://forms.gle/R6faU74qPRPAzchZ9
You may need to marshal all the settings held in viper into a string rather than write them to a file.
You need to set a key to Consul key/value storage with JSON value containing your desired config.
You would use the path "programmers.#.lastName" like such:
Zap takes a different approach. It includes a reflection-free, zero-allocation
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://dev.azure.com/pelletierthomas/go-toml-ci/_apis/build/status/pelletier.go-toml?branchName=master)](https://dev.azure.com/pelletierthomas/go-toml-ci/_build/latest?definitionId=1&branchName=master)
[![Build Status](https://github.com/mattn/go-colorable/workflows/test/badge.svg)](https://github.com/mattn/go-colorable/actions?query=workflow%3Atest)
[![Build Status](https://github.com/spf13/cast/actions/workflows/go.yml/badge.svg)](https://github.com/spf13/cast/actions/workflows/go.yml)
[![Build Status](https://travis-ci.org/chzyer/readline.svg?branch=master)](https://travis-ci.org/chzyer/readline)
[![Build Status](https://travis-ci.org/gorilla/mux.svg?branch=master)](https://travis-ci.org/gorilla/mux)
[![Build Status](https://travis-ci.org/miekg/dns.svg?branch=master)](https://travis-ci.org/miekg/dns)
[![Build Status](https://travis-ci.org/spf13/afero.svg)](https://travis-ci.org/spf13/afero) [![Build status](https://ci.appveyor.com/api/projects/status/github/spf13/afero?branch=master&svg=true)](https://ci.appveyor.com/project/spf13/afero) [![GoDoc](https://godoc.org/github.com/spf13/afero?status.svg)](https://godoc.org/github.com/spf13/afero) [![Join the chat at https://gitter.im/spf13/afero](https://badges.gitter.im/Dev%20Chat.svg)](https://gitter.im/spf13/afero?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/spf13/pflag.svg?branch=master)](https://travis-ci.org/spf13/pflag)
[![Build Status](https://travis-ci.org/subosito/gotenv.svg?branch=master)](https://travis-ci.org/subosito/gotenv)
[![Build Status](https://travis-ci.org/tidwall/rtree.svg?branch=master)](https://travis-ci.org/tidwall/rtree)
[![Build status](https://ci.appveyor.com/api/projects/status/wb2e075xkfl0m0v2/branch/master?svg=true)](https://ci.appveyor.com/project/subosito/gotenv/branch/master)
[![CircleCI](https://circleci.com/gh/gorilla/mux.svg?style=svg)](https://circleci.com/gh/gorilla/mux)
[![Code Coverage](https://img.shields.io/codecov/c/github/miekg/dns/master.svg)](https://codecov.io/github/miekg/dns?branch=master)
[![Codecov](https://codecov.io/gh/mattn/go-colorable/branch/master/graph/badge.svg)](https://codecov.io/gh/mattn/go-colorable)
[![Codecov](https://codecov.io/gh/mattn/go-isatty/branch/master/graph/badge.svg)](https://codecov.io/gh/mattn/go-isatty)
[![Coverage Status](https://badgen.net/codecov/c/github/subosito/gotenv)](https://codecov.io/gh/subosito/gotenv)
[![Coverage Status](https://coveralls.io/repos/github/mattn/go-isatty/badge.svg?branch=master)](https://coveralls.io/github/mattn/go-isatty?branch=master)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fpelletier%2Fgo-toml.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fpelletier%2Fgo-toml?ref=badge_shield)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/go-ini/ini/Go?logo=github&style=for-the-badge)](https://github.com/go-ini/ini/actions?query=workflow%3AGo)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/spf13/viper/CI?style=flat-square)](https://github.com/spf13/viper/actions?query=workflow%3ACI)
[![Go Reference](https://pkg.go.dev/badge/github.com/pelletier/go-toml.svg)](https://pkg.go.dev/github.com/pelletier/go-toml)
[![Go Report Card](https://goreportcard.com/badge/github.com/miekg/dns)](https://goreportcard.com/report/miekg/dns)
[![Go Report Card](https://goreportcard.com/badge/github.com/mwitkow/go-http-dialer)](http://goreportcard.com/report/mwitkow/go-http-dialer)
[![Go Report Card](https://goreportcard.com/badge/github.com/pelletier/go-toml)](https://goreportcard.com/report/github.com/pelletier/go-toml)
[![Go Report Card](https://goreportcard.com/badge/github.com/spf13/cast)](https://goreportcard.com/report/github.com/spf13/cast)
[![Go Report Card](https://goreportcard.com/badge/github.com/spf13/pflag)](https://goreportcard.com/report/github.com/spf13/pflag)
[![Go Report Card](https://goreportcard.com/badge/github.com/spf13/viper?style=flat-square)](https://goreportcard.com/report/github.com/spf13/viper)
[![Go Report Card](https://goreportcard.com/badge/github.com/subosito/gotenv)](https://goreportcard.com/report/github.com/subosito/gotenv)
[![Go Report Card](https://goreportcard.com/badge/mattn/go-colorable)](https://goreportcard.com/report/mattn/go-colorable)
[![Go Report Card](https://goreportcard.com/badge/mattn/go-isatty)](https://goreportcard.com/report/mattn/go-isatty)
[![GoDoc](http://img.shields.io/badge/GoDoc-Reference-blue.svg)](https://godoc.org/github.com/mwitkow/go-http-dialer)
[![GoDoc](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](http://godoc.org/github.com/magiconair/properties)
[![GoDoc](https://godoc.org/github.com/chzyer/readline?status.svg)](https://godoc.org/github.com/chzyer/readline)
[![GoDoc](https://godoc.org/github.com/elazarl/goproxy?status.svg)](https://godoc.org/github.com/elazarl/goproxy)
[![GoDoc](https://godoc.org/github.com/fsnotify/fsnotify?status.svg)](https://godoc.org/github.com/fsnotify/fsnotify) [![Go Report Card](https://goreportcard.com/badge/github.com/fsnotify/fsnotify)](https://goreportcard.com/report/github.com/fsnotify/fsnotify)
[![GoDoc](https://godoc.org/github.com/gorilla/mux?status.svg)](https://godoc.org/github.com/gorilla/mux)
[![GoDoc](https://godoc.org/github.com/hashicorp/hcl?status.png)](https://godoc.org/github.com/hashicorp/hcl) [![Build Status](https://travis-ci.org/hashicorp/hcl.svg?branch=master)](https://travis-ci.org/hashicorp/hcl)
[![GoDoc](https://godoc.org/github.com/mattn/go-colorable?status.svg)](http://godoc.org/github.com/mattn/go-colorable)
[![GoDoc](https://godoc.org/github.com/spf13/cast?status.svg)](https://godoc.org/github.com/spf13/cast)
[![GoDoc](https://godoc.org/github.com/spf13/pflag?status.svg)](https://godoc.org/github.com/spf13/pflag)
[![GoDoc](https://godoc.org/github.com/subosito/gotenv?status.svg)](https://godoc.org/github.com/subosito/gotenv)
[![GoDoc](https://godoc.org/github.com/tidwall/btree?status.svg)](https://godoc.org/github.com/tidwall/btree)
[![GoDoc](https://godoc.org/github.com/tidwall/match?status.svg)](https://godoc.org/github.com/tidwall/match)
[![GoDoc](https://godoc.org/github.com/tidwall/rtree?status.svg)](https://godoc.org/github.com/tidwall/rtree)
[![GoDoc](https://img.shields.io/badge/GoDoc-Reference-blue?style=for-the-badge&logo=go)](https://pkg.go.dev/github.com/go-ini/ini?tab=doc)
[![GoDoc](https://img.shields.io/badge/api-reference-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/tidwall/pretty) 
[![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov]
[![Go](https://github.com/klauspost/cpuid/actions/workflows/go.yml/badge.svg)](https://github.com/klauspost/cpuid/actions/workflows/go.yml)
[![Godoc Reference](https://godoc.org/github.com/mattn/go-isatty?status.svg)](http://godoc.org/github.com/mattn/go-isatty)
[![Join the chat at https://gitter.im/elazarl/goproxy](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/elazarl/goproxy?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Join the chat at https://gitter.im/spf13/viper](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/spf13/viper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg?style=flat-square)](https://raw.githubusercontent.com/magiconair/properties/master/LICENSE)
[![Matthew Holt speaking at dotGo 2016 about ACME in Go](https://user-images.githubusercontent.com/1128849/49921557-2d506780-fe6b-11e8-97bf-6053b6b4eb48.png)](https://www.dotconferences.com/2016/10/matthew-holt-go-with-acme)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/avelino/awesome-go#configuration)
[![Netflix/hal-9001](https://img.shields.io/github/stars/Netflix/hal-9001.svg?label=Netflix/hal-9001)](https://github.com/Netflix/hal-9001)
[![OpenCollective](https://opencollective.com/readline/badge/backers.svg)](#backers)
[![OpenCollective](https://opencollective.com/readline/badge/sponsors.svg)](#sponsors)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/klauspost/cpuid)](https://pkg.go.dev/github.com/klauspost/cpuid/v2)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/spf13/viper)](https://pkg.go.dev/mod/github.com/spf13/viper)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE.md)
[![Sourcegraph](https://img.shields.io/badge/view%20on-Sourcegraph-brightgreen.svg?style=for-the-badge&logo=sourcegraph)](https://sourcegraph.com/github.com/go-ini/ini)
[![Sourcegraph](https://sourcegraph.com/github.com/gorilla/mux/-/badge.svg)](https://sourcegraph.com/github.com/gorilla/mux?badge)
[![Travis Build](https://travis-ci.org/mwitkow/go-http-dialer.svg)](https://travis-ci.org/mwitkow/go-http-dialer)
[![Travis CI Status](https://img.shields.io/travis/magiconair/properties.svg?branch=master&style=flat-square&label=travis)](https://travis-ci.org/magiconair/properties)
[![Version](https://img.shields.io/github/tag/chzyer/readline.svg)](https://github.com/chzyer/readline/releases)
[![](https://godoc.org/github.com/miekg/dns?status.svg)](https://godoc.org/github.com/miekg/dns)
[![](https://img.shields.io/github/tag/magiconair/properties.svg?style=flat-square&label=release)](https://github.com/magiconair/properties/releases)
[![abiosoft/ishell](https://img.shields.io/github/stars/abiosoft/ishell.svg?label=abiosoft/ishell)](https://github.com/abiosoft/ishell)
[![bom-d-van/harp](https://img.shields.io/github/stars/bom-d-van/harp.svg?label=bom-d-van/harp)](https://github.com/bom-d-van/harp)
[![build](https://travis-ci.org/square/go-jose.svg?branch=v2)](https://travis-ci.org/square/go-jose)
[![cockroachdb](https://img.shields.io/github/stars/cockroachdb/cockroach.svg?label=cockroachdb/cockroach)](https://github.com/cockroachdb/cockroach)
[![codecov](https://codecov.io/gh/pelletier/go-toml/branch/master/graph/badge.svg)](https://codecov.io/gh/pelletier/go-toml)
[![codecov](https://img.shields.io/codecov/c/github/go-ini/ini/master?logo=codecov&style=for-the-badge)](https://codecov.io/gh/go-ini/ini)
[![coverage](https://coveralls.io/repos/github/square/go-jose/badge.svg?branch=v2)](https://coveralls.io/r/square/go-jose)
[![docker/go-p9p](https://img.shields.io/github/stars/docker/go-p9p.svg?label=docker/go-p9p)](https://github.com/docker/go-p9p)
[![empire](https://img.shields.io/github/stars/remind101/empire.svg?label=remind101/empire)](https://github.com/remind101/empire)
[![godoc](http://img.shields.io/badge/godoc-version_1-blue.svg?style=flat)](https://godoc.org/gopkg.in/square/go-jose.v1)
[![godoc](http://img.shields.io/badge/godoc-version_2-blue.svg?style=flat)](https://godoc.org/gopkg.in/square/go-jose.v2)
[![godoc](https://pkg.go.dev/badge/github.com/mholt/acmez)](https://pkg.go.dev/github.com/mholt/acmez)
[![knq/usql](https://img.shields.io/github/stars/knq/usql.svg?label=knq/usql)](https://github.com/knq/usql)
[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/go-jose/master/LICENSE)
[![license](https://img.shields.io/github/license/pelletier/go-toml.svg)](https://github.com/pelletier/go-toml/blob/master/LICENSE)
[![mehrdadrad/mylg](https://img.shields.io/github/stars/mehrdadrad/mylg.svg?label=mehrdadrad/mylg)](https://github.com/mehrdadrad/mylg)
[![robertkrimen/otto](https://img.shields.io/github/stars/robertkrimen/otto.svg?label=robertkrimen/otto)](https://github.com/robertkrimen/otto)
[![run on repl.it](https://repl.it/badge/github/sagikazarmark/Viper-example)](https://repl.it/@sagikazarmark/Viper-example#main.go)
[![youtube/doorman](https://img.shields.io/github/stars/youtube/doorman.svg?label=youtube/doorman)](https://github.com/youtube/doorman)
[#11]: https://github.com/fsnotify/fsnotify/issues/11
[#18]: https://github.com/fsnotify/fsnotify/issues/18
[#62]: https://github.com/howeyc/fsnotify/issues/62
[#7]: https://github.com/howeyc/fsnotify/issues/7
[1]: http://www.gnu.org/software/libc/manual/html_node/Argument-Syntax.html
[2]: http://localhost:6060/pkg/github.com/spf13/pflag
[3 8 2]
[3 9 1]
[3]: http://godoc.org/github.com/spf13/pflag
[4 7 4]
[4 8 3]
[5 6 6]
[5 7 5]
[CORSMethodMiddleware](https://godoc.org/github.com/gorilla/mux#CORSMethodMiddleware) intends to make it easier to strictly set the `Access-Control-Allow-Methods` response header.
[EasyJSON](https://github.com/mailru/easyjson),
[Evilginx 2.0 - Release](https://breakdev.org/evilginx-2-next-generation-of-phishing-2fa-tokens)
[Evilginx 2.1 - First Update](https://breakdev.org/evilginx-2-1-the-first-post-release-update/)
[Evilginx 2.2 - Jolly Winter Update](https://breakdev.org/evilginx-2-2-jolly-winter-update/)
[Evilginx 2.3 - Phisherman's Dream](https://breakdev.org/evilginx-2-3-phishermans-dream/)
[Evilginx 2.4 - Gone Phishing](https://breakdev.org/evilginx-2-4-gone-phishing/)
[Evilginx 3.0](https://breakdev.org/evilginx-3-0-evilginx-mastery/)
[Evilginx 3.2](https://breakdev.org/evilginx-3-2/)
[Evilginx 3.3](https://breakdev.org/evilginx-3-3-go-phish/)
[Exponential backoff][exponential backoff wiki]
[Hugo](http://hugo.spf13.com), a website engine which uses YAML, TOML or JSON
[JSON Web Encryption](http://dx.doi.org/10.17487/RFC7516) (RFC 7516),
[JSON Web Signature](http://dx.doi.org/10.17487/RFC7515) (RFC 7515), and
[JSON Web Token](http://dx.doi.org/10.17487/RFC7519) (RFC 7519).
[Jeevanandam M.](https://github.com/jeevatkm) (jeeva@myjeeva.com)
[LICENSE.txt](https://github.com/spf13/afero/blob/master/LICENSE.txt)
[MIT License]: LICENSE.txt
[Postgres]
[See full godoc for detailed documentation.](https://pkg.go.dev/github.com/libdns/libdns)
[Version 2](https://gopkg.in/square/go-jose.v2)
[[Become a backer](https://opencollective.com/readline#backer)]
[`jose-util`](https://github.com/square/go-jose/tree/v2/jose-util)
[advanced example]: https://godoc.org/github.com/cenkalti/backoff#example_
[at godoc.org][3], or through go's standard documentation system by
[benchmarking suite]: https://github.com/uber-go/zap/tree/master/benchmarks
[benchmarks/go.mod]: https://github.com/uber-go/zap/blob/master/benchmarks/go.mod
[ci-img]: https://github.com/uber-go/multierr/actions/workflows/go.yml/badge.svg
[ci-img]: https://github.com/uber-go/zap/actions/workflows/go.yml/badge.svg
[ci]: https://github.com/uber-go/multierr/actions/workflows/go.yml
[ci]: https://github.com/uber-go/zap/actions/workflows/go.yml
[contributing]: https://github.com/fsnotify/fsnotify/blob/master/CONTRIBUTING.md
[cov-img]: https://codecov.io/gh/uber-go/multierr/branch/master/graph/badge.svg
[cov-img]: https://codecov.io/gh/uber-go/zap/branch/master/graph/badge.svg
[cov]: https://codecov.io/gh/uber-go/multierr
[cov]: https://codecov.io/gh/uber-go/zap
[coveralls image]: https://coveralls.io/repos/github/cenkalti/backoff/badge.svg?branch=master
[coveralls]: https://coveralls.io/github/cenkalti/backoff?branch=master
[doc-img]: https://pkg.go.dev/badge/go.uber.org/multierr
[doc-img]: https://pkg.go.dev/badge/go.uber.org/zap
[doc](https://godoc.org/gopkg.in/square/go-jose.v2)) is the current version:
[doc]: https://pkg.go.dev/go.uber.org/multierr
[doc]: https://pkg.go.dev/go.uber.org/zap
[dockerhub](https://hub.docker.com/r/pelletier/go-toml). For example, to
[exponential backoff wiki]: http://en.wikipedia.org/wiki/Exponential_backoff
[ffjson](https://github.com/pquerna/ffjson), 
[godoc image]: https://godoc.org/github.com/cenkalti/backoff?status.png
[godoc]: https://godoc.org/github.com/cenkalti/backoff
[google-http-java-client]: https://github.com/google/google-http-java-client/blob/da1aa993e90285ec18579f1553339b00e19b3ab5/google-http-client/src/main/java/com/google/api/client/util/ExponentialBackOff.java
[http://localhost:6060/pkg/github.com/spf13/pflag][2] after
[jsonparser](https://github.com/buger/jsonparser),
[jwt](https://godoc.org/gopkg.in/square/go-jose.v2/jwt) implementation
[libucl](https://github.com/vstakhov/libucl),
[multipath](SYNTAX.md#multipaths) syntax. For backwards compatibility, 
[nearing completion][v2-map].
[pelletier/go-toml](https://github.com/pelletier/go-toml). Any feedback would be
[pkg.go.dev](https://pkg.go.dev/github.com/pelletier/go-toml).
[postgres]
[table-driven tests](https://dave.cheney.net/2013/06/09/writing-table-driven-tests-in-go) to test multiple
[the eavesdropper example](https://github.com/elazarl/goproxy/blob/master/examples/goproxy-eavesdropper/main.go#L27)
[travis image]: https://travis-ci.org/cenkalti/backoff.png?branch=master
[travis]: https://travis-ci.org/cenkalti/backoff
[v1-bugs]: https://github.com/pelletier/go-toml/issues?q=is%3Aissue+is%3Aopen+label%3Av2-fixed
[v1.0.0-rc.3](https://toml.io/en/v1.0.0-rc.3)
[v2-bench]: https://github.com/pelletier/go-toml/tree/v2#benchmarks
[v2-dev]: https://github.com/pelletier/go-toml/tree/v2
[v2-map]: https://github.com/pelletier/go-toml/discussions/506
[v2]: https://github.com/pelletier/go-toml/tree/v2
\* Android and iOS are untested.
_, err := client.R().
_, err := fs.Create("/file.html")
_, err := fs.Create("/file.txt")
_Why 7 levels?_
`
`#[...]` will continue to work until the next major release.*
`${GOOS}/Dockerfile` to checkout the new release of the source.
`)
`--no-color` bool flag. You can easily disable the color output with:
`AppFs` being the variable we defined above.
`AutomaticEnv` is a powerful helper especially when combined with
`BindEnv` takes one or more parameters. The first parameter is the key name, the
`Color` has support to disable/enable colors programatically both globally and
`DoFunc` will process all incoming requests to the proxy. It will add a header to the request
`DoFunc` will receive a function that will preprocess the request. We can change the request, or
`DstHostIs` returns a `ReqCondition`, that is a function receiving a `Request` and returning a boolean.
`FlagValueSet` represents a group of flags. This is a very simple example on how to implement this interface:
`FlagValue` represents a single flag. This is a very simple example on how to implement this interface:
`GOOGLE_APPLICATION_CREDENTIALS_JSON` env variable to your JSON credentials or use `opts` in
`Get()` calls, but want your environmental variables to use `_` delimiters. An
`NewGcsFS` to configure access to your GCS bucket.
`NewSigner`. Each of these keys can also be wrapped in a JWK if desired, which
`OnEvent` can return an error. Some events may be aborted by returning an error. For example, returning an error from `cert_obtained` can cancel obtaining the certificate. Only return an error from `OnEvent` if you want to abort program flow.
`Parse` ignores invalid lines and returns `Env` of valid environment variables, while `StrictParse` returns an error for invalid lines.
`PathPrefix("/static/").Handler(...)` means that the handler will be passed any
`SetEnvKeyReplacer` allows you to use a `strings.Replacer` object to rewrite Env
`SetEnvPrefix`. When called, Viper will check for an environment variable any
`SugaredLogger`. It's 4-10x faster than other structured logging
`_errors.c`, which prints out all the constants.
```
``` go
``` json
```Go
```bash
```console
```go
```json
```sh
```shell
```yaml
`amd64` has rather good support and should work reliably on all platforms.
`arm64/darwin` adds features expected from the M1 processor, but a lot remains undetected.
`crypt` has a command-line helper that you can use to put configurations in your
`datastore.metric.port` are already defined (and may be overridden). If in addition
`datastore.metric.protocol` was defined in the defaults, Viper would also find it.
`fmt.Fprintf` to log tons of `interface{}`s makes your application slow.
`go get -u github.com/klauspost/cpuid/v2` using modules.
`go get -u go.uber.org/zap`
`go install github.com/klauspost/cpuid/v2/cmd/cpuid@latest`
`go test ./...`
`go-http-dialer` is released under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
`go-isatty` package will automatically disable color output for non-tty output streams 
`import _ "github.com/spf13/viper/remote"`
`init()` function.
`libdns` is a collection of free-range DNS provider client implementations written in Go! With libdns packages, your Go program can manage DNS records across any supported providers. A "provider" is a service or program that manages a DNS zone.
`localhost:8080`, as this is the default binding for the basic proxy.
`multierr` allows combining one or more Go `error`s together.
`pflag` allows you to disable sorting of flags for help and usage message.
`syscall_${GOOS}.go`.
`types_${GOOS}.go` on the old system). This file includes standard C headers and
`ztypes_${GOOS}_${GOARCH}.go`.
a `ReqCondition` accepting only requests directed to "www.reddit.com".
a configuration language shouldn't usually allow, and also forces
a flag has a NoOptDefVal and the flag is set on the command line without
a: Easy!
acmez - ACME client library for Go
afs := &afero.Afero{Fs: fs}
age: 35
allocation and when they'd prefer a more familiar, loosely typed API.
allows attaching a key id.
also implement your own required configuration source and feed it to viper.
amw := authenticationMiddleware{}
amw.Populate()
an option the flag will be set to the NoOptDefVal. For example given:
an ordered, mutable data structure.
analogous to the top-level functions for the command-line
anchors, tags, map merging, etc. Multi-document unmarshalling is not yet
and Encryption set of standards. This includes support for JSON Web Encryption,
and GOARCH. Generated by mksysnum (see above).
and JSON as the interoperability layer.
and [in Firefox](http://www.wikihow.com/Enter-Proxy-Settings-in-Firefox).
and [json-iterator](https://github.com/json-iterator/go)
and [much faster][v2-bench]. If you only need reading and writing TOML documents
and a wide variety of miscellaneous constants. The constants come from the list
and allocations wherever possible. By building the high-level `SugaredLogger`
and benefit of the os and ioutil packages.
and can be written to the output.
and easier to reuse (for the same reason).
and formats. It supports:
and have each OS upgrade correspond to a single change.
and it must be an int. GetString("flagname") will fail.
and list `//sys` comments giving prototypes for ones that can be generated.
and make many small allocations. Put differently, using `encoding/json` and
and pass it to a module. This way the module can be instantiated more than once, with different configurations.
and return it. The proxy will send the modified request.
and some people wanted machine-friendly languages.
and the file access would be fast while also saving you from all the annoying
and then you will not need to run with root privileges.
and there is no safe way to do so for the rest.
and use this library to decode it into the proper underlying native Go
and vice versa, while providing helpful error handling.
appfs := afero.NewOsFs()
appfs.MkdirAll("src/a", 0755)
application foundation needs.
applications out of the box. There are five methods that exist to aid working
appropriate in my application code. This approach ensures that Tests are order
architecture. This also means that the generated code can differ from system
architecture/OS or to add additional syscalls, types, or constants. Note that
arguments can be passed to the kernel. The third is for low-level use by the
array   >> []interface{}
as an example.
as an input so that it is also machine-friendly (machines can generate
as customizable as goproxy intends to be. The main difference is, Fiddler is not
as used in the [Cobra](https://github.com/spf13/cobra) library.
avoiding breaking changes wherever reasonable. We support the last two versions of Go.
b:
backed file implementation. This can be used in other memory backed file
backend is perfect for testing.
backend. To do this I would define my `appFS = afero.NewOsFs()` somewhere
backends.
base := afero.NewOsFs()
bazel test :resty_test
be used to perform file operations over a encrypted channel.
beard: true
before their development.
before this terminator.
benchmarking against slightly older versions of other packages. Versions are
blue := color.New(color.FgBlue)
blue := color.New(color.FgBlue).FprintfFunc()
blue(myWriter, "important notice: %s", stars)
blue.Fprint(writer, "This will print text in blue.")
boldRed := red.Add(color.Bold)
boldRed.Println("This will print text in bold red.")
bool, for JSON booleans
boolean >> bool
bp := afero.NewBasePathFs(afero.NewOsFs(), "/base/path")
branch. Version 2 also contains additional sub-packages such as the
buntdb.Desc(buntdb.IndexJSON("age")))
buntdb.IndexJSON("name.last"),
buntdb.Open(":memory:") // Open a file that does not persist to disk.
but
but it would require weird concatenation for accessing config keys and would be less separated from the global config.
by HashiCorp. The goal of HCL is to build a structured configuration language
by a calling a convenience function provided by the pflag package called
bytes, _ := ioutil.ReadAll(vhostConn)
c := color.New(color.FgCyan)
c := color.New(color.FgCyan).Add(color.Underline)
c.DisableColor()
c.EnableColor()
c.Println("Prints cyan text with an underline.")
c.Println("Prints cyan text")
c.Println("This is printed without any color")
c.Println("This prints again cyan...")
cache = certmagic.NewCache(certmagic.CacheOptions{
cache1 := NewCache(cache1Config)
cache1Config := viper.Sub("cache.cache1")
cache:
caching layer.
call dispatch. There are three entry points:
calls. It also makes it trivial to have your code use the OS during
can build servers and resolvers with it.
can build your own image as usual:
can decide what verbose means to you or even have multiple levels of
can set it to afero.NewMemMapFs().
can use GetInt() to get the int value. But notice that 'flagname' must exist
cast
cert1, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
cert1, err := tls.X509KeyPair([]byte("-----BEGIN CERTIFICATE-----content-----END CERTIFICATE-----"), []byte("-----BEGIN CERTIFICATE-----content-----END CERTIFICATE-----"))
certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
certmagic.Default.OnDemand = new(certmagic.OnDemandConfig)
certmagic.DefaultACME.Agreed = true
certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
certmagic.DefaultACME.Email = "you@yours.com"
certmagic.HTTPS([]string{"example.com"}, mux)
change.
changed from `panic` to `log.Fatal` but this is configurable and custom
changed in v1.3.0 as to avoid confusion with the new
check for an environment variable with a name matching the key uppercased and
check out [GJSON Syntax](SYNTAX.md).
cipherSuites := vhost.ClientHelloMsg.CipherSuites
client := acmez.Client{
client := resty.New()
client := resty.New().
client.
client.AddRetryCondition(
client.OnAfterResponse(func(c *resty.Client, resp *resty.Response) error {
client.OnBeforeRequest(func(c *resty.Client, req *resty.Request) error {
client.OnError(func(req *resty.Request, err error) {
client.R().Get("http://localhost/index.html")
client.R().SetPathParams(map[string]string{
client.R().SetQueryString("productId=232&template=fresh-sample&cat=resty&source=google&kw=buy a lot more")
client.RemoveProxy()
client.SetAllowGetMethodPayload(true)
client.SetAuthToken("BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F")
client.SetBaseURL("http://httpbin.org")
client.SetBasicAuth("myuser", "mypass")
client.SetCertificates(cert1, cert2, cert3)
client.SetContentLength(true)
client.SetCookie(&http.Cookie{
client.SetCookies(cookies)
client.SetDebug(true)
client.SetError(&Error{})    // or resty.SetError(Error{})
client.SetFormData(map[string]string{
client.SetHeader("Accept", "application/json")
client.SetHeaders(map[string]string{
client.SetOutputDirectory("/Users/jeeva/Downloads")
client.SetProxy("http://proxyserver:8888")
client.SetQueryParam("user_id", "00001")
client.SetQueryParams(map[string]string{ // sample of those who use this manner
client.SetRedirectPolicy(CustomRedirectPolicy{/* initialize variables */})
client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(15))
client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(20),
client.SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
client.SetRootCertificate("/path/to/root/pemFile1.pem")
client.SetRootCertificate("/path/to/root/pemFile2.pem")
client.SetRootCertificateFromString("-----BEGIN CERTIFICATE-----content-----END CERTIFICATE-----")
client.SetTLSClientConfig(&tls.Config{ InsecureSkipVerify: true })
client.SetTLSClientConfig(&tls.Config{ RootCAs: roots })
client.SetTimeout(1 * time.Minute)
client.SetTransport(&transport).SetScheme("http").SetBaseURL(unixSocket)
client.SetXMLMarshaler(xml.Marshal).
client1 := resty.New()
client1.R().Get("http://httpbin.org")
client2 := resty.New()
client2.R().Head("http://httpbin.org")
clothing:
color.Blue("Prints %s in blue.", "text")
color.Cyan("Prints text in cyan.")
color.Magenta("And many others ..")
color.New(color.FgBlue).Fprintln(myWriter, "blue color!")
color.Red("We have red")
color.Set(color.FgMagenta, color.Bold)
color.Set(color.FgYellow)
color.Unset() // Don't forget to unset
comparison operators and the simple pattern matching `%` (like) and `!%` 
completely blank state every time it is initialized and can be easily
components of the build system change.
config := Config{}
config file, environment variable, remote configuration or flag.
config, _ := toml.Load(`
configurable by providing a custom `ErrorHandler` function. The default has
configuration file formats; you want to focus on building awesome software.
configuration from the K/V store, which means that you can store your
configuration level.
configuration values encrypted and have them automatically decrypted if you have
conn, _ := listener.Accept()
connection using "Man in the Middle" style attack.
const json = `{"name":{"first":"Janet","last":"Prichard"},"age":47}`
constants to an existing architecture/OS pair requires some manual effort;
constants.
contributed by [@shaxbee](https://github.com/shaxbee).
converted. Using these methods you can tell the difference between when the
could use the `httpmock` library.
created in the overlay.
creates Go type aliases to the corresponding C types. The file is then fed
criteria := url.Values{
ctx := context.TODO()
curl localhost:8080/foo -v
currently a single Viper instance only supports a single configuration file.
customRouting := vhost.Request.Header["X-Custom-Routing-Header"]
d := color.New(color.FgCyan, color.Bold)
d.Printf("This prints bold cyan %s\n", "too!.")
data. It's ideal for projects that need a dependable database and favor
database, use the `buntdb.Open()` function:
date=$(git show ${tag}^0 --format=%aD | head -1)
db, _ := buntdb.Open(":memory:")
db.CreateIndex("ages", "user:*:age", buntdb.IndexInt)
db.CreateIndex("amount", "*", collate.IndexString("FRENCH_NUM"))
db.CreateIndex("last_name", "*", collate.IndexJSON("CHINESE_CI", "name.last"))
db.CreateIndex("last_name_age", "*",
db.CreateIndex("last_name_age", "*", buntdb.IndexJSON("name.last"), buntdb.IndexJSON("age"))
db.CreateIndex("name", "*", collate.IndexString("FRENCH_CI"))
db.CreateIndex("names", "*", buntdb.IndexString)
db.CreateIndex("names", "user:*", buntdb.IndexString)
db.CreateSpatialIndex("fleet", "fleet:*:pos", buntdb.IndexRect)
db.Update(func(tx *buntdb.Tx) error {
db.View(func(tx *buntdb.Tx) error {
decoding of the JSON (reading the "type" first, and the rest later).
default values, but are overridden by configuration values retrieved from disk,
defer color.Unset() // Use it in your function
defer logger.Sync()
defer logger.Sync() // flushes buffer, if any
defined for the flag package by importing these flags. This is accomplished
del key:2
deletedRecs, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
details.
development is frozen. All new feature development takes place on the `v2`
different config file, key value store, etc. All of the functions that viper
different than a double dash. Single dashes signify a series of shorthand
different vipers.
directly permitting the request is within the cache duration of when it was
directory, and the build is coordinated by the `${GOOS}/mkall.go` program. When
disable/enable color output on the fly:
doc := []byte(`
docker build -t go-toml .
docker run -v $PWD:/workdir pelletier/go-toml tomljson /workdir/example.toml
document or just characters.
done first to the base, then to the overlay layer. Write calls to open file
each GOOS/GOARCH pair.
echo "Updating $tag"
email=$(git show ${tag}^0 --format=%aE | head -1)
ended up guessing more often than not whether to use a hyphen, colon, etc.
err := certmagic.HTTPS([]string{"example.com", "www.example.com"}, mux)
err := db.Update(func(tx *buntdb.Tx) error {
err := db.View(func(tx *buntdb.Tx) error {
err := gotenv.Load(".env-is-not-exist")
err := magic.ManageSync(context.TODO(), []string{"example.com", "sub.example.com"})
err := runtime_viper.ReadRemoteConfig()
err := viper.ReadInConfig() // Find and read the config file
err := viper.ReadRemoteConfig()
err := viper.Unmarshal(&C)
err, pairs = gotenv.StrictParse(strings.NewReader(`FOO="bar"`))
error handling functions can be provided. See the package documentation for
etc.
example of using it can be found in `viper_test.go`.
example, if the following JSON file is loaded:
execute after the change was made.
expected on it. When v2.0.0 is released, v1 will be deprecated.
exported or re-exported in any form or on any media to Iran, North Sudan,
eyes : brown
f, err := afero.TempFile(fs,"", "ioutil-test")
f, err := afs.TempFile("", "ioutil-test")
fSet := myFlagSet{
faster than the `SugaredLogger` and allocates far less, but it only supports
file (if it is not already there) and add in a type alias line. Note that if
file system.
fileBytes, _ := os.ReadFile("/Users/jeeva/mydocument.pdf")
files on an installation with unmodified header files. It is also important to
fileserver := http.FileServer(httpFs.Dir(<PATH>))
filesystem for full interoperability.
filesystems that make it easy to work with afero while retaining all the power
flag set.
flag.Lookup("flagname").NoOptDefVal = "4321"
flag.Parse()
flag.Var(&flagVal, "name", "help message for flagname")
flag.VarP(&flagVal, "varname", "v", "help message")
flags can be interspersed with arguments anywhere on the command line
flags, or environment variables.
flags.BoolP("verbose", "v", false, "verbose output")
flags.Int("usefulflag", 777, "sometimes it's very useful")
flags.MarkDeprecated("badflag", "please use --good-flag instead")
flags.MarkHidden("secretFlag")
flags.MarkShorthandDeprecated("noshorthandflag", "please use --noshorthandflag only")
flags.PrintDefaults()
flags.SortFlags = false
flags.String("coolflag", "yeaah", "it's really cool flag")
float64, for JSON numbers
fmt.Fprintf(color.Output, "Windows support: %s", color.GreenString("PASS"))
fmt.Printf("%s", bytes)
fmt.Printf("%v %v\n", color.GreenString("Info:"), "an important message.")
fmt.Printf("Target Host: ", vhostConn.Host())
fmt.Printf("This %s rocks!\n", info("package"))
fmt.Printf("This is a %s and this is %s.\n", yellow("warning"), red("error"))
fmt.Printf("This one %s\n", "too")
fmt.Println("  Body       :\n", resp)
fmt.Println("  ConnIdleTime  :", ti.ConnIdleTime)
fmt.Println("  ConnTime      :", ti.ConnTime)
fmt.Println("  DNSLookup     :", ti.DNSLookup)
fmt.Println("  Error      :", err)
fmt.Println("  IsConnReused  :", ti.IsConnReused)
fmt.Println("  IsConnWasIdle :", ti.IsConnWasIdle)
fmt.Println("  Proto      :", resp.Proto())
fmt.Println("  Received At:", resp.ReceivedAt())
fmt.Println("  RemoteAddr    :", ti.RemoteAddr.String())
fmt.Println("  RequestAttempt:", ti.RequestAttempt)
fmt.Println("  ResponseTime  :", ti.ResponseTime)
fmt.Println("  ServerTime    :", ti.ServerTime)
fmt.Println("  Status     :", resp.Status())
fmt.Println("  Status Code:", resp.StatusCode())
fmt.Println("  TCPConnTime   :", ti.TCPConnTime)
fmt.Println("  TLSHandshake  :", ti.TLSHandshake)
fmt.Println("  Time       :", resp.Time())
fmt.Println("  TotalTime     :", ti.TotalTime)
fmt.Println("All text will now be bold magenta.")
fmt.Println("Existing text will now be in yellow")
fmt.Println("Request Trace Info:")
fmt.Println("Response Info:")
fmt.Println("This", color.RedString("warning"), "should be not neglected.")
fmt.Println("error", err)
fmt.Println("flagvar has value ", flagvar)
fmt.Println("ip has value ", *ip)
fmt.Println("user=", config.Postgres.User)
fmt.Println()
fmt.Println(os.Getenv("HELLO"))
fmt.Println(viper.Get("hostname")) // myhostname.com
fmt.Println(viper.Get("port")) // 8080
foo
for _, k := range delkeys {
for _, name := range result.Array() {
for _, v := range virtualHosts {
for a given GOOS/GOARCH pair must be generated on a system with that OS and
for a library that allows one to make files and directories and do things with them.
for command-line options][1]. For a more precise description, see the
for dealing with JOSE messages in a shell.
for example you can only convert a string to an int when it is a string
for ii, item := range results.Values() {
for meta data.
for single color definitions. For example suppose you have a CLI app and a
for the old system). This program takes in a list of header files containing the
for {
friends.#(age>45)#.last            >> ["Craig","Murphy"]
friends.#(first!%"D*").last        >> "Craig"
friends.#(first%"D*").last         >> "Murphy"
friends.#(last=="Murphy")#.first   >> ["Dale","Jane"]
friends.#(last=="Murphy").first    >> "Dale"
friends.#(nets.#(=="fb"))#.first   >> ["Dale","Roger"]
from one type into another. Cast goes beyond just using type assertion (though
from source checkouts of the kernel and various system libraries. This means
from the base to the overlay when they're not present (or outdated) in the
from the bytes of the encoded format. This is great, but the problem is if
from the generated architecture-specific files listed below, and merge these
fs := afero.NewMemMapFs()
fs := afero.NewReadOnlyFs(afero.NewOsFs())
fs := afero.NewRegexpFs(afero.NewMemMapFs(), regexp.MustCompile(`\.txt$`))
fs := new(afero.MemMapFs)
fsnotify is a fork of [howeyc/fsnotify](https://godoc.org/github.com/howeyc/fsnotify) with a new API as of v1.0. The API is based on [this design document](http://goo.gl/MrYxyA). 
fsnotify requires support from underlying OS to work. The current NFS protocol does not provide network level support for file notifications.
fsnotify utilizes [golang.org/x/sys](https://godoc.org/golang.org/x/sys) rather than `syscall` from the standard library. Ensure you have the latest version installed by running:
full types, then Cast is the library for you.
func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
func (amw *authenticationMiddleware) Populate() {
func (c *CustomRedirectPolicy) Apply(req *http.Request, via []*http.Request) error {
func (f myFlag) HasChanged() bool { return false }
func (f myFlag) Name() string { return "my-flag-name" }
func (f myFlag) ValueString() string { return "my-flag-value" }
func (f myFlag) ValueType() string { return "string" }
func (f myFlagSet) VisitAll(fn func(FlagValue)) {
func (i1 *Item) Less(item btree.Item, ctx interface{}) bool {
func ArticlesCategoryHandler(w http.ResponseWriter, r *http.Request) {
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
func NewCache(v *Viper) *Cache {
func ServeHTTP(w http.ResponseWriter, req *http.Request) {
func TestExist(t *testing.T) {
func TestHealthCheckHandler(t *testing.T) {
func TestMetricsHandler(t *testing.T) {
func YourHandler(w http.ResponseWriter, r *http.Request) {
func aliasNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
func fooHandler(w http.ResponseWriter, r *http.Request) {
func handler(w http.ResponseWriter, r *http.Request) {
func init() {
func loggingMiddleware(next http.Handler) http.Handler {
func main() {
func wordSepNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
func yamlStringSettings() string {
functions as methods to a given filesystem.
functions such as String(), BoolVar(), and Var(), and is therefore
get the real ones.
github.com/miekg/dns`).
gjson.AddModifier("case", func(json, arg string) string {
gjson.ForEachLine(json, func(line gjson.Result) bool{
gjson.Get(json, "name").Get("last")
gjson.Get(json, "name.last")
gjson.Parse(json).Get("name").Get("last")
go func(){
go get -u github.com/gorilla/mux
go get -u github.com/tidwall/collate
go get -u github.com/tidwall/match
go get -u go.uber.org/multierr@latest
go get -u golang.org/x/sys/...
go get github.com/fatih/color
go get github.com/spf13/viper
go get github.com/tidwall/buntdb-benchmark
go test --bench=.
go-vhost is a simple library that lets you implement virtual hosting functionality for different protocols (HTTP and TLS so far). go-vhost has a high-level and a low-level interface. The high-level interface lets you wrap existing net.Listeners with "muxer" objects. You can then Listen() on a muxer for a particular virtual host name of interest which will return to you a net.Listener for just connections with the virtual hostname of interest.
goproxy server. Fiddler is a GUI app not designed to be run like a server for multiple users.
gotenv.Apply(strings.NewReader("APP_ID=1234567"))
gotenv.Apply(strings.NewReader("HELLO=universe"))
gotenv.Load(".env.production", "credentials")
gotenv.Must(gotenv.Load, ".env-is-not-exist")
gotenv.OverApply(strings.NewReader("HELLO=universe"))
had a really hard time determining what the actual structure was, and
hand-written Go files which implement system calls (for unix, the specific OS,
handle).
handles like `Write()` or `Truncate()` to the overlay first.
has been provided.
has support for Windows too! The API can be used in several ways, pick one that
have discarded the request and sent the new response to the client.
have its own unique set of configurations and values. Each can read from a
hello
hobbies:
host, err := r.Get("article").URLHost("subdomain", "news")
how to use Consul.
however, there are tools that automate much of the process.
http.Handle("/", fileserver)
http.ListenAndServe(":80", mux)
http.ListenAndServe(":80", myACME.HTTPChallengeHandler(mux))
httpFs := afero.NewHttpFs(<ExistingFS>)
httpMux = myACME.HTTPChallengeHandler(httpMux)
httpVersion := vhost.Request.MinorVersion
httpmock.ActivateNonDefault(client.GetClient())
https://academy.breakdev.org/evilginx-mastery
https://help.evilginx.com
https://www.gorillatoolkit.org/pkg/mux
httpsHandlers   []HttpsHandler
i := viper.GetInt("flagname") // retrieve values from viper instead of pflag
i, err := flagset.GetInt("flagname")
id := Get("id") // 13
id="anchor-versions">[1](#footnote-versions)</sup>
if !gjson.Valid(json) {
if !ok {
if !value.Exists() {
if *flagNoColor {
if cache1Config == nil { // Sub returns nil if the key cannot be found
if err != nil {
if err != nil { // Handle errors reading the config file
if err := db.ReadConfig(&config); err != nil{
if err := db.WriteConfig(config); err != nil{
if err := viper.ReadInConfig(); err != nil {
if gjson.Get(json, "name.last").Exists() {
if result.Index > 0 {
if vhostConn, err = vhost.HTTP(conn); err != nil {
if vhostConn, err = vhost.TLS(conn); err != nil {
if viper.GetBool("verbose") {
if you are using the new build system, the scripts/programs cannot be called normally.
implement:
implemented, and base-60 floats from YAML 1.1 are purposefully not
implemented. [Reference](retry_test.go).
import "github.com/go-resty/resty/v2"
import "github.com/libdns/cloudflare"
import "github.com/pelletier/go-toml"
import "github.com/spf13/afero"
import "github.com/subosito/gotenv"
import "github.com/tidwall/collate"
import "github.com/tidwall/gjson"
import (
import flag "github.com/spf13/pflag"
import jsoniter "github.com/json-iterator/go"
importantly doesn't support comments. With YAML, we found that beginners
in a Key/Value store such as etcd or Consul.  These values take precedence over
in a command-line interface. The methods of FlagSet are
in order to gradually find an acceptable rate.
in order to represent some configuration key.
include and which symbols need to be `#define`d to get the actual data
including you! Details are in the [contribution guide](CONTRIBUTING.md) and
independent sets of flags, such as to implement subcommands
independent, with no test relying on the state left by an earlier test.
independently of it.
independently, together they make a powerful pair to handle much of your
indexes that are sorted by the specified language. This is similar to the [SQL COLLATE keyword](https://msdn.microsoft.com/en-us/library/ms174596.aspx) found in traditional databases.
info := color.New(color.FgWhite, color.BgGreen).SprintFunc()
initialization needed to begin using Viper. Since most applications will want
input matched the zero value or when the conversion failed and the zero value
installation.
intended to be used as a real proxy.
interacting with any filesystem, as an abstraction layer providing interfaces,
interface into a bool, etc. Cast does this intelligently when an obvious
interoperable with other systems.
into a common file for each OS.
io.Closer
io.Reader
io.ReaderAt
io.Seeker
io.Writer
io.WriterAt
is an algorithm that uses feedback to multiplicatively decrease the rate of some process,
is fed though mkpost.go to format the code correctly and remove any hidden or
is the library for you.
isatty for golang
isn't a convenience function for it. Server side and client side programming is supported, i.e. you
issues and pull requests, but you can also report any negative conduct to
issues with deleting temporary files, Windows file locking, etc. The MemMapFs
it **does not** automatically add the prefix. For example if the second parameter is "id",
it difficult to keep up with all of the pointers in your code.
it is accessed. This means you can bind as early as you want, even in an
it uses that when possible) to provide a very straightforward and convenient
it will detect CPU features, but may crash if the OS doesn't intercept the calls.
it will override the default retry behavior, which retries on errors encountered during the request.
jWalterWeatherman
json := jsoniter.ConfigCompatibleWithStandardLibrary
json.
just include the error numbers and error strings, but also the signal numbers
keep track of which version of the OS the files were generated from (ex.
keys to an extent. This is useful if you want to use `-` or something in your
l, _ := net.Listen("tcp", *listen)
layer := afero.NewMemMapFs()
layer into the overlay. Subsequent reads will be pulled from the overlay
learned is that some people wanted human-friendly configuration languages
leaving the base filesystem (OsFs) untouched.
let it know that a system call is running.
letters for flags. All but the last shorthand letter must be boolean flags
level before making any other calls if you want to see what it's up to.
libdns - Universal DNS provider APIs for Go
libraries in other languages.
library, and can be passed to corresponding functions such as `NewEncrypter` or
library.
like in `/home/${USER}/myapp.properties`.
ln, err := certmagic.Listen([]string{"example.com"})
ln, err := tls.Listen("tcp", ":443", myTLSConfig)
log.Println(os.Getenv("APP_ID"))
logger, _ := zap.NewProduction()
logger.Info("failed to fetch URL",
logrus.Error("something error")
logrus.Fatal("panic")
logrus.Info("succeeded")
logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
logrus.SetOutput(colorable.NewColorableStdout())
logrus.Warn("not correct")
m, ok := gjson.Parse(json).Value().(map[string]interface{})
magic := certmagic.New(cache, certmagic.Config{
magic := certmagic.NewDefault()
magic.Issuers = []certmagic.Issuer{myACME}
maintainers don't have access, so don't hesitate to hold us to a high
map[a:Easy! b:map[c:2 d:[3 4]]]
mapstructure is a Go library for decoding generic map values to structures
match a syscall number in the `zsysnum_${GOOS}_${GOARCH}.go` file. The function
match.Match("hello", "*llo") 
match.Match("hello", "h*o") 
match.Match("jello", "?ello") 
matches with `#(...)#`. Queries support the `==`, `!=`, `<`, `<=`, `>`, `>=` 
means "forever" meaning the file will not be re-requested from the base ever.
memory backed file system during testing. It also adds support for the http
migrating the build system to use containers so the builds are reproducible.
mm := afero.NewMemMapFs()
mm.MkdirAll("src/a", 0755)
module:
much appreciated!
multiple recipients. It also comes with a small command-line utility
mux := http.NewServeMux()
mux, _ := vhost.NewHTTPMuxer(l, muxTimeout)
mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
myACME := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
myACME := certmagic.NewACMEIssuer(magic, certmagic.DefaultACME)
myFlagSet.SetNormalizeFunc(aliasNormalizeFunc)
myFlagSet.SetNormalizeFunc(wordSepNormalizeFunc)
myTLSConfig.GetCertificate = magic.GetCertificate
myTLSConfig.NextProtos = append(myTLSConfig.NextProtos, tlsalpn01.ACMETLS1Protocol)
myTLSConfig.NextProtos = append(myTLSConfig.NextProtos, tlsalpn01.ACMETLS1Protocol}
name := gjson.Get(json, `programmers.#(lastName="Hunter").firstName`)
name: steve
name=$(git show ${tag}^0 --format=%aN | head -1)
necessary. It is fully concurrent and will work within go routines
new build system). However, depending on the OS, you may need to update the
new installation of the target OS (or updating the source checkouts for the
newRecs, err := provider.SetRecords(ctx, zone, []libdns.Record{
nginx configuration, and others similar.
nil, for JSON null
no additional information is currently available. 
not Fiddler, is gathering statistics on page load times for a certain website over a week.
not miss a beat.
notably the ability to create mock and testing filesystems without relying on the disk.
notepad = jww.NewNotepad(jww.LevelInfo, jww.LevelTrace, os.Stdout, ioutil.Discard, "", log.Ldate|log.Ltime)
notepad.WARN.Println("Some warning"")
notesBytes, _ := os.ReadFile("/Users/jeeva/text-file.txt")
notice := color.New(color.Bold, color.FgGreen).PrintlnFunc()
notice("Don't forget this...")
null    >> nil
number  >> float64
number characters and '?' matches on any one character.
object  >> map[string]interface{}
object of a particular type".
of [TOML](https://github.com/toml-lang/toml) is indicated at the beginning of
of [case-insensitive matching](https://www.ietf.org/mail-archive/web/json/current/msg03763.html)).
of include files in the `includes_${uname}` variable. A regex then picks out
of releases. Users of semver-aware dependency management systems should pin
of the syntax and grammar is listed here.
on that foundation, zap lets users *choose* when they need to count every
one are provided, they will take precedence in the specified order. The name of
operation and a mock filesystem during testing or as needed.
or
or a flag with a default value
or lower case.
or the specific OS/Architecture pair respectively) that need special handling
os.Open("/tmp/foo")
os.Setenv("HELLO", "world")
os.Setenv("SPF_ID", "13") // typically done outside of the app
oss-conduct@uber.com. That email list is a private, safe space; even the zap
overlay layer before modification (including opening a file with a writable
overlay will be removed/renamed.
package as it provides an additional abstraction that makes it easy to use a
package from the standard library. The pflag package can handle the flags
package main
package supports are mirrored as methods on a viper.
package:
packages and includes both structured and `printf`-style APIs.
pairs := gotenv.Parse(strings.NewReader("FOO=test\nBAR=$FOO"))
parsing in mksysnum.
part of the [juju](https://juju.ubuntu.com) project, and is based on a
password := postgresConfig.Get("password").(string)
password = "mypassword"`)
path, err := r.Get("article").URLPath("category", "technology", "id", "42")
people to learn some set of Ruby.
permitted. If a file is present in the base layer and the overlay, only the
pflag is a drop-in replacement for Go's flag package, implementing
pflag is a drop-in replacement of Go's native flag package. If you import
pflag is available under the same style of BSD license as the Go language,
pflag is available using the standard `go get` command.
pflag is compatible with the [GNU extensions to the POSIX recommendations
pflag under the name "flag" then all code should continue to function
pflag.Int("flagname", 1234, "help message for flagname")
pflag.Parse()
pointer receivers) and couple them to flag parsing by
possible route variables as needed.
postgresConfig := config.Get("postgres").(*toml.Tree)
prefix.
prefixed with the `EnvPrefix` if set.
present on your system. This means that files
preset alternate versions for binary compatibility and translate them on the
println(name.String())  // prints "Elliotte"
private identifiers. This cleaned-up code is written to
profileImgBytes, _ := os.ReadFile("/Users/jeeva/test-img.png")
properties is a Go library for reading and writing properties files.
property expansion of expressions like `${key}` to their corresponding value.
prototype can be exported (capitalized) or not.
provider := cloudflare.Provider{APIToken: "topsecret"}
provides a few advantages over using the standard log library alone.
provides this. It is similar to a singleton.
proxy. Here is how you do that [in Chrome](https://support.google.com/chrome/answer/96815?hl=en)
proxy.OnRequest().DoFunc(
proxy.OnRequest(Some ReqConditions).Do(YourReqHandlerFunc())
proxy.OnRequest(Some ReqConditions).HandleConnect(YourHandlerFunc())
proxy.OnRequest(goproxy.DstHostIs("www.reddit.com")).DoFunc(
proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("reddit.*:443$"))).HandleConnect(goproxy.AlwaysReject)
proxy.OnRequest(goproxy.UrlMatches(regexp.MustCompile(`.*gif$`))).Do(YourReqHandlerFunc())
proxy.OnRequest(goproxy.UrlMatches(regexp.MustCompile(`.*gif$`))).HandleConnect(goproxy.AlwaysReject)
proxy.OnResponse(Some RespConditions).Do(YourRespHandlerFunc())
pure Go port of the well-known [libyaml](http://pyyaml.org/wiki/LibYAML)
q, _ := query.Compile("$..[user,password]")
r := mux.NewRouter()
r.HandleFunc("/", handler)
r.HandleFunc("/articles/{category}/", ArticlesCategoryHandler)
r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
r.HandleFunc("/products", ProductsHandler).
r.HandleFunc("/products/{key}", ProductHandler)
r.HandleFunc("/specific", specificHandler)
r.Headers("X-Requested-With", "XMLHttpRequest")
r.HeadersRegexp("Content-Type", "application/(text|json)")
r.Host("www.example.com")
r.Host("{subdomain:[a-z]+}.example.com")
r.Host("{subdomain}.example.com").
r.MatcherFunc(func(r *http.Request, rm *RouteMatch) bool {
r.Methods("GET", "POST")
r.PathPrefix("/").Handler(catchAllHandler)
r.PathPrefix("/products/")
r.Queries("key", "value")
r.Schemes("https")
r.Use(amw.Middleware)
r.Use(loggingMiddleware)
readers and a single writer. It supports custom indexes and geospatial
recs, err := provider.GetRecords(ctx, zone)
red := color.New(color.FgRed)
red := color.New(color.FgRed).PrintfFunc()
red := color.New(color.FgRed).SprintFunc()
red("Error: %s", err)
red("Warning")
reference for this package. The
reqHandlers     []ReqHandler 
request that matches "/static/\*". This makes it easy to serve static files with mux:
require github.com/go-resty/resty/v2 v2.11.0
resp, err := client.R().
respHandlers    []RespHandler 
rest are the name of the environment variables to bind to this key. If more than
result := gjson.Get(json, "programmers")
result := gjson.Get(json, "programmers.#.lastName")
result := gjson.GetBytes(json, path)
result = pretty.Color(json, nil)
result = pretty.Pretty(example)
result = pretty.Ugly(example)
result.Array() []gjson.Result
result.Bool() bool
result.Exists() bool
result.Float() float64
result.ForEach(func(key, value gjson.Result) bool {
result.ForEach(iterator func(key, value Result) bool)
result.Get(path string) Result
result.Index          // index of raw value in original json, zero means index unknown
result.Indexes        // indexes of all the elements that match on a path containing the '#' query character.
result.Int() int64
result.Int() int64    // -9223372036854775808 to 9223372036854775807
result.Less(token Result, caseSensitive bool) bool
result.Map() map[string]gjson.Result
result.Num            // holds the float64 number
result.Raw            // holds the raw json
result.Str            // holds the string
result.String() string
result.Time() time.Time
result.Type           // can be String, Number, True, False, Null, or JSON
result.Uint() int64   // 0 to 18446744073709551615
result.Uint() uint64
result.Value() interface{}
results := gjson.GetMany(json, "name.first", "name.last", "age")
results := q.Execute(config)
retain the commit date, name and email address. Please run `git pull --tags` to update them.
return a pre-canned text response saying "do not waste your time".
return a response. If the time is between 8:00am and 17:00pm, we will reject the request, and
returns an http.File type.
run [go-fuzz](https://github.com/dvyukov/go-fuzz) on go-toml.
running `godoc -http=:6060` and browsing to
runtime_viper.AddRemoteProvider("etcd", "http://127.0.0.1:4001", "/config/hugo.yml")
runtime_viper.SetConfigType("yaml") // because there is no file extension in a stream of bytes, supported extensions are "json", "toml", "yaml", "yml", "properties", "props", "prop", "env", "dotenv"
runtime_viper.Unmarshal(&runtime_conf)
s := r.Host("www.example.com").Subrouter()
s := r.Host("{subdomain}.example.com").Subrouter()
s := r.PathPrefix("/products").Subrouter()
s.HandleFunc("/", ProductsHandler)
s.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
s.HandleFunc("/products/", ProductsHandler)
s.HandleFunc("/products/{key}", ProductHandler)
s.HandleFunc("/{key}/", ProductHandler)
s.HandleFunc("/{key}/details", ProductDetailsHandler)
s.Path("/articles/{category}/{id:[0-9]+}").
safely.
serve the file from the base.
serverCmd.Flags().Int("port", 1138, "Port to run Application server on")
sessionId := vhost.ClientHelloMsg.SessionId
set key:1 value1
set key:1 value3
set key:2 value2
shortly. While pull-requests are welcome on v1, no active development is
signal numbers and strings are generated from `#include <signal.h>`. All of
signal numbers, and constants. Generated by `mkerrors.sh` (see above).
simply exports the file system variable for easy access from anywhere.
slice flag.Args() or individually as flag.Arg(i).
so even if your host supports a feature it may not be visible on guests.
solver := &certmagic.DNS01Solver{
some `#if/#elif` macros in your include statements.
specific fields. For example, consider this JSON:
specifically targeted towards DevOps tools, servers, etc.
speed over data size.
standard library which uses case-sensitive matching for member names (instead
standard library. Like all benchmarks, take these with a grain of salt.<sup
standard usage. Eg.
standard where possible. The Godoc reference has a list of constants.
standard.
still receive backported bug fixes and security fixes, but otherwise
string  >> string
string formatting are prohibitively expensive &mdash; they're CPU-intensive
string, for JSON string literals
struct tags.
structure, read the "type" key, then use something like this library
structure.
structured logging.
structures that pass through to the kernel system calls. Some C libraries
style approach.
subdirectory also contains a small command-line utility which might be useful
success := color.New(color.Bold, color.FgGreen).FprintlnFunc()
success(myWriter, "Don't forget this...")
such as Ruby to complete data structure languages such as JSON. What we
sugar := logger.Sugar()
sugar.Infof("Failed to fetch URL: %s", url)
sugar.Infow("failed to fetch URL",
suits you.
supported since they're a poor design and are gone in YAML 1.2.
syscall number declarations and parses them to produce the corresponding list of
system and have your GOOS and GOARCH set accordingly. Running `mkall.sh` will
system can be generated at once, and generated files will not change based on
system using InMemoryFile.
system, or you can declare a new `Afero`, a custom type used to bind these
system. Running `mkall.sh -n` shows the commands that will be run.
systems with ease. Plans are to add a radix tree memory stored file
tag=$1
than comparable structured logging packages &mdash; it's also faster than the
that give one-letter shorthands for flags. You can use these by appending
that is JSON-compatible. Our configuration language (HCL) is designed
that is both human and machine friendly for use with command-line tools, but
that on any platform that supports Docker, all the files using the new build
that you should be using all 7 levels. Pick the right set for your needs.
the "type" field from the JSON. We could always do two passes over the
the To_____ methods, plus an additional error which tells you if it successfully
the U.S. Export Administration Regulations. You may not export, re-export,
the [code of conduct](CODE_OF_CONDUCT.md). The zap maintainers keep an eye on
the `AllowEmptyEnv` method.
the `BindEnv` is called.
the ability to drop in other filesystems as desired.
the base path before calling the source Fs.
the code for a complete set.
the compact and full serialization formats, and has optional support for
the correct gpg keyring.  Encryption is optional.
the desired `#define` statements, and generates the corresponding Go constants.
the desired type. **If input is provided that will not convert to that type, the
the environment variable is case sensitive. If the ENV variable name is not provided, then
the environment variables. Both `BindEnv` and `AutomaticEnv` will use this
the following prints all of the registered routes:
the following should work:
the following things.
the given flag. Doing this changes the meaning of the flag slightly. If
the kernel or system library updates, modify the Dockerfile at
the names in the [JSON Web Algorithms](http://dx.doi.org/10.17487/RFC7518)
the next configuration source. To treat empty environment variables as set, use
the passed regexp will be treated as non-existing.
the regex too broad to avoid matching unintended constants.
the same concept but as a noun it means "something that is made or done" or "an
the use of other packages that use the [flag](https://golang.org/pkg/flag/)
their respective handler.
them directly where the first parameter of each function will be the file
them into syscalls. This requires the name of the prototype in the comment to
then generate all of the files for all of the GOOS/GOARCH pairs in the new build
there is one more field "Shorthand" that you will need to set.
these constants are written to `zerrors_${GOOS}_${GOARCH}.go` via a C program,
they are all pointers; if you bind to variables, they're values.
this document. The last two major versions of Go are supported
through godef to get the Go compatible definitions. Finally, the generated code
ti := resp.Request.TraceInfo()
time a `viper.Get` request is made. It will apply the following rules. It will
tinyqueue is a Go package for binary heap priority queues.
tlsConfig := magic.TLSConfig()
tlsConfig, err := certmagic.TLS([]string{"example.com"})
tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
to [Cobra](https://github.com/spf13/cobra). While both can operate completely
to an application.
to be written and modified by humans. The API for HCL allows JSON
to decode it into the proper structure.
to increase retry intervals after each attempt.
to parse the command line into the defined flags.
to support flags defined by third-party dependencies (e.g. `golang/glog`).
to system, based on differences in the header files.
to use a single central repository for their configuration, the viper package
to work within an application, and can handle all types of configuration needs
toml.Unmarshal(doc, &config)
top-level functions.  The FlagSet type allows one to define
transfer or download this code or any part of it in violation of any United
transport := http.Transport{
treats ENV variables as case sensitive._
tx.AscendKeys("object:*", func(k, v string) bool {
tx.Intersects("points", "[-inf -inf 2],[+inf +inf 4]", func(key, val string) bool {
type Config struct {
type CustomRedirectPolicy struct {
type Item struct {
type MiddlewareFunc func(http.Handler) http.Handler
type Options struct {
type Postgres struct {
type T struct {
type authenticationMiddleware struct {
type config struct {
type moduleConfig struct {
type myFlag struct {}
type myFlagSet struct {
types and methods. Afero has an exceptionally clean interface and simple design
ufs := afero.NewCacheOnReadFs(base, layer, 100 * time.Second)
unaffected.
underlying operating system. See: https://godoc.org/golang.org/x/sys/unix
unexported `//sys` prototype, and then write a custom wrapper in
unixSocket := "/var/run/my_socket.sock"
until you read a part of it. You can therefore read a `map[string]interface{}`
upstreamHost := hostMapping[vhostConn.Host()]
url, err := r.Get("article").URL("category", "technology", "id", "42")
url, err := r.Get("article").URL("subdomain", "news",
use `tomljson`:
used a variety of configuration languages from full programming languages
user := config.Get("postgres.user").(string)
user = "pelletier"
user:0:age 35
user:0:name tom
user:1 Jane
user:1:age 49
user:1:name Randi
user:2 Andy
user:2:age 13
user:2:name jane
user:3 Steve
user:4 Andrea
user:4:age 63
user:4:name Janet
user:5 Janet
user:5:age 8
user:5:name Paula
user:6 Andy
user:6:age 3
user:6:name peter
user:7:age 16
user:7:name Terri
using `SetEnvPrefix`, you can tell Viper to use a prefix while reading from
v := viper.NewWithOptions(viper.KeyDelimiter("::"))
v.SetDefault("chart::values", map[string]interface{}{
v.Unmarshal(&C)
valid input to a system expecting HCL. This helps makes systems
value := gjson.Get(json, "name.last")
value will be read each time it is accessed. Viper does not fix the value when
values. It was developed within [Canonical](https://www.canonical.com) as
var AppFs = afero.NewMemMapFs()
var AppFs = afero.NewOsFs()
var C config
var cache *certmagic.Cache
var config buntdb.Config
var data = `
var delkeys []string
var flagNoColor = flag.Bool("no-color", false, "Disable color output")
var flagvar bool
var flagvar int
var ip *int = flag.Int("flagname", 1234, "help message for flagname")
var ip = flag.IntP("flagname", "f", 1234, "help message")
var json []byte = ...
var raw []byte
var runtime_viper = viper.New()
var yamlExample = []byte(`
variable "ami" {
variable is set (regardless of its value).
variables like in `${USER}`.  Filenames can also contain environment variables
variables, flags, and remote K/V store, but you are not bound to them. You can
verbosity.
very easy to use as all of the calls are the same as the existing OS
vhostConn.Free()
via the union Fs).
viper powered applications can read an update to a config file while running and
viper.AddConfigPath("$HOME/.appname")  // call multiple times to add many search paths
viper.AddConfigPath(".")               // optionally look for config in the working directory
viper.AddConfigPath("/etc/appname/")   // path to look for the config file in
viper.AddRemoteProvider("consul", "localhost:8500", "MY_CONSUL_KEY")
viper.AddRemoteProvider("etcd", "http://127.0.0.1:4001","/config/hugo.json")
viper.AddRemoteProvider("firestore", "google-cloud-project-id", "collection/document")
viper.AddSecureRemoteProvider("etcd","http://127.0.0.1:4001","/config/hugo.json","/etc/secrets/mykeyring.gpg")
viper.BindFlagValue("my-flag-name", myFlag{})
viper.BindFlagValues("my-flags", fSet)
viper.BindPFlag("port", serverCmd.Flags().Lookup("port"))
viper.BindPFlags(pflag.CommandLine)
viper.Get("name") // this would be "steve"
viper.GetBool("loud") // true
viper.GetBool("verbose") // true
viper.GetString("logfile") // case-insensitive Setting & Getting
viper.OnConfigChange(func(e fsnotify.Event) {
viper.ReadConfig(bytes.NewBuffer(yamlExample))
viper.RegisterAlias("loud", "Verbose")
viper.SafeWriteConfig()
viper.SafeWriteConfigAs("/path/to/my/.config") // will error since it has already been written
viper.SafeWriteConfigAs("/path/to/my/.other_config")
viper.Set("LogFile", LogFile)
viper.Set("Verbose", true)
viper.Set("loud", true)   // same result as prior line
viper.Set("verbose", true) // same result as next line
viper.SetConfigName("config") // name of config file (without extension)
viper.SetConfigType("json") // Config's format: "json", "toml", "yaml", "yml"
viper.SetConfigType("json") // Need to explicitly set this to json
viper.SetConfigType("json") // because there is no file extension in a stream of bytes,  supported extensions are "json", "toml", "yaml", "yml", "properties", "props", "prop", "env", "dotenv"
viper.SetConfigType("json") // because there is no file extension in a stream of bytes, supported extensions are "json", "toml", "yaml", "yml", "properties", "props", "prop", "env", "dotenv"
viper.SetConfigType("yaml") // REQUIRED if the config file does not have the extension in the name
viper.SetConfigType("yaml") // or viper.SetConfigType("YAML")
viper.SetDefault("ContentDir", "content")
viper.SetDefault("LayoutDir", "layouts")
viper.SetDefault("Taxonomies", map[string]string{"tag": "tags", "category": "categories"})
viper.WatchConfig()
viper.WriteConfig() // writes current config to predefined path set by 'viper.AddConfigPath()' and 'viper.SetConfigName'
viper.WriteConfigAs("/path/to/my/.config")
was returned.
way in and out of system calls, but there is almost always a `#define` that can
we'll get `children` array and reverse the order:
what the person running the scripts has installed on their computer.
where a configuration file is expected.
which can be found in the LICENSE file.
whiteBackground := red.Add(color.BgWhite)
whiteBackground.Println("Red text with white background.")
widget.image.hOffset
widget.text.onMouseUp
widget.window.name
will be returned instead. E.g.
will be using a completely new and isolated filesystem. In the case of
will cascade through the remaining configuration registries until found.
with ENV:
with no changes.
with the delay increasing after each attempt.
with the desired arguments and a capitalized name so it is exported. However, if
without needless constructors or initialization methods.
world
would.
writeable layer on top.
x := viper.New()
x.SetDefault("ContentDir", "content")
y := viper.New()
y.SetDefault("ContentDir", "foobar")
yellow := color.New(color.FgYellow).SprintFunc()
yet customizable and programmable.
you have configuration or an encoding that changes slightly depending on
you have to change the delimiter:
you want the interface to the syscall to be different, often one will make an
you'll need to configure it as follows:
your specific system. Running `mkall.sh -n` shows the commands that will be run.
your type is significantly different on different architectures, you may need
zap to `^1`.
zone := "example.com."
{
{"name":  {"first":"Tom","last":"Anderson"},  "age":37,
{"name": "Alexa", "age": 34}
{"name": "Deloise", "age": 44}
{"name": "Gilbert", "age": 61}
{"name": "May", "age": 57}
{"name":{"first":"Tom","last":"Anderson"},"age":37,"children":["Sara","Alex","Jack"],"fav.movie":"Deer Hunter","friends":[{"first":"Janet","last":"Murphy","age":44}]}```
{Easy! {2 [3 4]}}
|          |             |             |            | |                  |                  |             |
| -------------    | -------------   |
| --------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| --flagname       | ip=4321         |
| --flagname=1357  | ip=1357         |
| 256 b    |   `553ns`   |   `557ns`   |   `441ns`  | |  `463MB/s`       |  `459MB/s`       |  `580MB/s`  |
| 256 b  |  `364ns`    |   `250ns`  | |  `703MB/s`       |  `1.03GB/s`  |
| 512 b    |   `948ns`   |   `953ns`   |   `841ns`  | |  `540MB/s`       |  `538MB/s`       |  `609MB/s`  |
| 512 b  |  `575ns`    |   `468ns`  | |  `892MB/s`       |  `1.10GB/s`  |
| 64 b     |   `253ns`   |   `254ns`   |   `134ns`  | |  `253MB/s`       |  `252MB/s`       |  `478MB/s`  |
| 64 b   |  `205ns`    |  `86.5ns`  | |  `312MB/s`       |   `740MB/s`  |
| 768 b  |  `795ns`    |   `682ns`  | |  `967MB/s`       |  `1.13GB/s`  |
| :------ | :--: | :-----------: | :---------------: |
| :zap: zap (sugared) | 81 ns/op | +29% | 1 allocs/op
| :zap: zap (sugared) | 84 ns/op | +25% | 1 allocs/op
| :zap: zap (sugared) | 935 ns/op | +43% | 10 allocs/op
| :zap: zap | 63 ns/op | +0% | 0 allocs/op
| :zap: zap | 656 ns/op | +0% | 5 allocs/op
| :zap: zap | 67 ns/op | +0% | 0 allocs/op
| ADX                | Intel ADX (Multi-Precision Add-Carry Instruction Extensions)                                                                                                                       |
| AESARM       | AES instructions                                                 |
| AESNI              | Advanced Encryption Standard New Instructions                                                                                                                                      |
| AMD3DNOW           | AMD 3DNOW                                                                                                                                                                          |
| AMD3DNOWEXT        | AMD 3DNowExt                                                                                                                                                                       |
| AMXBF16            | Tile computational operations on BFLOAT16 numbers                                                                                                                                  |
| AMXFP16            | Tile computational operations on FP16 numbers                                                                                                                                      |
| AMXINT8            | Tile computational operations on 8-bit integers                                                                                                                                    |
| AMXTILE            | Tile architecture                                                                                                                                                                  |
| APX_F              | Intel APX                                                                                                                                                                          |
| ARMCPUID     | Some CPU ID registers readable at user-level                     |
| ASIMD        | Advanced SIMD                                                    |
| ASIMDDP      | SIMD Dot Product                                                 |
| ASIMDHP      | Advanced SIMD half-precision floating point                      |
| ASIMDRDM     | Rounding Double Multiply Accumulate/Subtract (SQRDMLAH/SQRDMLSH) |
| ATOMICS      | Large System Extensions (LSE)                                    |
| AVX                | AVX functions                                                                                                                                                                      |
| AVX10              | If set the Intel AVX10 Converged Vector ISA is supported                                                                                                                           |
| AVX10_128          | If set indicates that AVX10 128-bit vector support is present                                                                                                                      |
| AVX10_256          | If set indicates that AVX10 256-bit vector support is present                                                                                                                      |
| AVX10_512          | If set indicates that AVX10 512-bit vector support is present                                                                                                                      |
| AVX2               | AVX2 functions                                                                                                                                                                     |
| AVX512BF16         | AVX-512 BFLOAT16 Instructions                                                                                                                                                      |
| AVX512BITALG       | AVX-512 Bit Algorithms                                                                                                                                                             |
| AVX512BW           | AVX-512 Byte and Word Instructions                                                                                                                                                 |
| AVX512CD           | AVX-512 Conflict Detection Instructions                                                                                                                                            |
| AVX512DQ           | AVX-512 Doubleword and Quadword Instructions                                                                                                                                       |
| AVX512ER           | AVX-512 Exponential and Reciprocal Instructions                                                                                                                                    |
| AVX512F            | AVX-512 Foundation                                                                                                                                                                 |
| AVX512FP16         | AVX-512 FP16 Instructions                                                                                                                                                          |
| AVX512IFMA         | AVX-512 Integer Fused Multiply-Add Instructions                                                                                                                                    |
| AVX512PF           | AVX-512 Prefetch Instructions                                                                                                                                                      |
| AVX512VBMI         | AVX-512 Vector Bit Manipulation Instructions                                                                                                                                       |
| AVX512VBMI2        | AVX-512 Vector Bit Manipulation Instructions, Version 2                                                                                                                            |
| AVX512VL           | AVX-512 Vector Length Extensions                                                                                                                                                   |
| AVX512VNNI         | AVX-512 Vector Neural Network Instructions                                                                                                                                         |
| AVX512VP2INTERSECT | AVX-512 Intersect for D/Q                                                                                                                                                          |
| AVX512VPOPCNTDQ    | AVX-512 Vector Population Count Doubleword and Quadword                                                                                                                            |
| AVXIFMA            | AVX-IFMA instructions                                                                                                                                                              |
| AVXNECONVERT       | AVX-NE-CONVERT instructions                                                                                                                                                        |
| AVXSLOW            | Indicates the CPU performs 2 128 bit operations instead of one                                                                                                                     |
| AVXVNNI            | AVX (VEX encoded) VNNI neural network instructions                                                                                                                                 |
| AVXVNNIINT8        | AVX-VNNI-INT8 instructions                                                                                                                                                         |
| Adapter               | OS                               | Status                                                                                                                          |
| BHI_CTRL           | Branch History Injection and Intra-mode Branch Target Injection / CVE-2022-0001, CVE-2022-0002 / INTEL-SA-00598                                                                    |
| BMI1               | Bit Manipulation Instruction Set 1                                                                                                                                                 |
| BMI2               | Bit Manipulation Instruction Set 2                                                                                                                                                 |
| CETIBT             | Intel CET Indirect Branch Tracking                                                                                                                                                 |
| CETSS              | Intel CET Shadow Stack                                                                                                                                                             |
| CLDEMOTE           | Cache Line Demote                                                                                                                                                                  |
| CLMUL              | Carry-less Multiplication                                                                                                                                                          |
| CLZERO             | CLZERO instruction supported                                                                                                                                                       |
| CMOV               | i686 CMOV                                                                                                                                                                          |
| CMPCCXADD          | CMPCCXADD instructions                                                                                                                                                             |
| CMPSB_SCADBS_SHORT | Fast short CMPSB and SCASB                                                                                                                                                         |
| CMPXCHG8           | CMPXCHG8 instruction                                                                                                                                                               |
| CPBOOST            | Core Performance Boost                                                                                                                                                             |
| CPPC               | AMD: Collaborative Processor Performance Control                                                                                                                                   |
| CRC32        | CRC32/CRC32C instructions                                        |
| CX16               | CMPXCHG16B Instruction                                                                                                                                                             |
| DCPOP        | Data cache clean to Point of Persistence (DC CVAP)               |
| EFER_LMSLE_UNS     | AMD: =Core::X86::Msr::EFER[LMSLE] is not supported, and MBZ                                                                                                                        |
| ENQCMD             | Enqueue Command                                                                                                                                                                    |
| ERMS               | Enhanced REP MOVSB/STOSB                                                                                                                                                           |
| EVTSTRM      | Generic timer                                                    |
| F16C               | Half-precision floating-point conversion                                                                                                                                           |
| FCMA         | Floatin point complex number addition and multiplication         |
| FEN                   | Solaris 11                       | [In Progress](https://github.com/fsnotify/fsnotify/issues/12)                                                                   |
| FLUSH_L1D          | Flush L1D cache                                                                                                                                                                    |
| FMA3               | Intel FMA 3. Does not imply AVX.                                                                                                                                                   |
| FMA4               | Bulldozer FMA4 functions                                                                                                                                                           |
| FP           | Single-precision and double-precision floating point             |
| FP128              | AMD: When set, the internal FP/SIMD execution datapath is 128-bits wide                                                                                                            |
| FP256              | AMD: When set, the internal FP/SIMD execution datapath is 256-bits wide                                                                                                            |
| FPHP         | Half-precision floating point                                    |
| FSEvents              | macOS                            | [Planned](https://github.com/fsnotify/fsnotify/issues/11)                                                                       |
| FSRM               | Fast Short Rep Mov                                                                                                                                                                 |
| FXSR               | FXSAVE, FXRESTOR instructions, CR4 bit 9                                                                                                                                           |
| FXSROPT            | FXSAVE/FXRSTOR optimizations                                                                                                                                                       |
| Feature Flag       | Description                                                                                                                                                                        |
| Feature Flag | Description                                                      |
| GFNI               | Galois Field New Instructions. May require other features (AVX, AVX512VL,AVX512F) based on usage.                                                                                  |
| GPA          | Generic Pointer Authentication                                   |
| HLE                | Hardware Lock Elision                                                                                                                                                              |
| HRESET             | If set CPU supports history reset and the IA32_HRESET_ENABLE MSR                                                                                                                   |
| HTT                | Hyperthreading (enabled)                                                                                                                                                           |
| HWA                | Hardware assert supported. Indicates support for MSRC001_10                                                                                                                        |
| HYBRID_CPU         | This part has CPUs of more than one type.                                                                                                                                          |
| HYPERVISOR         | This bit has been reserved by Intel & AMD for use by hypervisors                                                                                                                   |
| IA32_ARCH_CAP      | IA32_ARCH_CAPABILITIES MSR (Intel)                                                                                                                                                 |
| IA32_CORE_CAP      | IA32_CORE_CAPABILITIES MSR                                                                                                                                                         |
| IBPB               | Indirect Branch Restricted Speculation (IBRS) and Indirect Branch Predictor Barrier (IBPB)                                                                                         |
| IBRS               | AMD: Indirect Branch Restricted Speculation                                                                                                                                        |
| IBRS_PREFERRED     | AMD: IBRS is preferred over software solution                                                                                                                                      |
| IBRS_PROVIDES_SMP  | AMD: IBRS provides Same Mode Protection                                                                                                                                            |
| IBS                | Instruction Based Sampling (AMD)                                                                                                                                                   |
| IBSBRNTRGT         | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSFETCHSAM        | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSFFV             | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSOPCNT           | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSOPCNTEXT        | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSOPSAM           | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSRDWROPCNT       | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBSRIPINVALIDCHK   | Instruction Based Sampling Feature (AMD)                                                                                                                                           |
| IBS_FETCH_CTLX     | AMD: IBS fetch control extended MSR supported                                                                                                                                      |
| IBS_OPDATA4        | AMD: IBS op data 4 MSR supported                                                                                                                                                   |
| IBS_OPFUSE         | AMD: Indicates support for IbsOpFuse                                                                                                                                               |
| IBS_PREVENTHOST    | Disallowing IBS use by the host supported                                                                                                                                          |
| IBS_ZEN4           | Fetch and Op IBS support IBS extensions added with Zen4                                                                                                                            |
| IDPRED_CTRL        | IPRED_DIS                                                                                                                                                                          |
| INT_WBINVD         | WBINVD/WBNOINVD are interruptible.                                                                                                                                                 |
| INVLPGB            | NVLPGB and TLBSYNC instruction supported                                                                                                                                           |
| JSCVT        | Javascript-style double->int convert (FJCVTZS)                   |
| KEYLOCKER          | Key locker                                                                                                                                                                         |
| KEYLOCKERW         | Key locker wide                                                                                                                                                                    |
| LAHF               | LAHF/SAHF in long mode                                                                                                                                                             |
| LAM                | If set, CPU supports Linear Address Masking                                                                                                                                        |
| LBRVIRT            | LBR virtualization                                                                                                                                                                 |
| LRCPC        | Weaker release consistency (LDAPR, etc)                          |
| LZCNT              | LZCNT instruction                                                                                                                                                                  |
| MCAOVERFLOW        | MCA overflow recovery support.                                                                                                                                                     |
| MCDT_NO            | Processor do not exhibit MXCSR Configuration Dependent Timing behavior and do not need to mitigate it.                                                                             |
| MCOMMIT            | MCOMMIT instruction supported                                                                                                                                                      |
| MD_CLEAR           | VERW clears CPU buffers                                                                                                                                                            |
| MMX                | standard MMX                                                                                                                                                                       |
| MMXEXT             | SSE integer functions or AMD MMX ext                                                                                                                                               |
| MOVBE              | MOVBE instruction (big-endian)                                                                                                                                                     |
| MOVDIR64B          | Move 64 Bytes as Direct Store                                                                                                                                                      |
| MOVDIRI            | Move Doubleword as Direct Store                                                                                                                                                    |
| MOVSB_ZL           | Fast Zero-Length MOVSB                                                                                                                                                             |
| MOVU               | MOVU SSE instructions are more efficient and should be preferred to SSE	MOVL/MOVH. MOVUPS is more efficient than MOVLPS/MOVHPS. MOVUPD is more efficient than MOVLPD/MOVHPD        |
| MPX                | Intel MPX (Memory Protection Extensions)                                                                                                                                           |
| MSRIRC             | Instruction Retired Counter MSR available                                                                                                                                          |
| MSRLIST            | Read/Write List of Model Specific Registers                                                                                                                                        |
| MSR_PAGEFLUSH      | Page Flush MSR available                                                                                                                                                           |
| NRIPS              | Indicates support for NRIP save on VMEXIT                                                                                                                                          |
| NX                 | NX (No-Execute) bit                                                                                                                                                                |
| OSXSAVE            | XSAVE enabled by OS                                                                                                                                                                |
| PCONFIG            | PCONFIG for Intel Multi-Key Total Memory Encryption                                                                                                                                |
| PMULL        | Polynomial Multiply instructions (PMULL/PMULL2)                  |
| POPCNT             | POPCNT instruction                                                                                                                                                                 |
| PPIN               | AMD: Protected Processor Inventory Number support. Indicates that Protected Processor Inventory Number (PPIN) capability can be enabled                                            |
| PREFETCHI          | PREFETCHIT0/1 instructions                                                                                                                                                         |
| PSFD               | Predictive Store Forward Disable                                                                                                                                                   |
| Package | Time | Time % to zap | Objects Allocated |
| Parsed Arguments | Resulting Value |
| Polling               | *All*                            | [Maybe](https://github.com/fsnotify/fsnotify/issues/9)                                                                          |
| RDPRU              | RDPRU instruction supported                                                                                                                                                        |
| RDRAND             | RDRAND instruction is available                                                                                                                                                    |
| RDSEED             | RDSEED instruction is available                                                                                                                                                    |
| RDTSCP             | RDTSCP Instruction                                                                                                                                                                 |
| RRSBA_CTRL         | Restricted RSB Alternate                                                                                                                                                           |
| RTM                | Restricted Transactional Memory                                                                                                                                                    |
| RTM_ALWAYS_ABORT   | Indicates that the loaded microcode is forcing RTM abort.                                                                                                                          |
| ReadDirectoryChangesW | Windows                          | Supported |
| SERIALIZE          | Serialize Instruction Execution                                                                                                                                                    |
| SEV                | AMD Secure Encrypted Virtualization supported                                                                                                                                      |
| SEV_64BIT          | AMD SEV guest execution only allowed from a 64-bit host                                                                                                                            |
| SEV_ALTERNATIVE    | AMD SEV Alternate Injection supported                                                                                                                                              |
| SEV_DEBUGSWAP      | Full debug state swap supported for SEV-ES guests                                                                                                                                  |
| SEV_ES             | AMD SEV Encrypted State supported                                                                                                                                                  |
| SEV_RESTRICTED     | AMD SEV Restricted Injection supported                                                                                                                                             |
| SEV_SNP            | AMD SEV Secure Nested Paging supported                                                                                                                                             |
| SGX                | Software Guard Extensions                                                                                                                                                          |
| SGXLC              | Software Guard Extensions Launch Control                                                                                                                                           |
| SHA                | Intel SHA Extensions                                                                                                                                                               |
| SHA1         | SHA-1 instructions (SHA1C, etc)                                  |
| SHA2         | SHA-2 instructions (SHA256H, etc)                                |
| SHA3         | SHA-3 instructions (EOR3, RAXI, XAR, BCAX)                       |
| SHA512       | SHA512 instructions                                              |
| SM3          | SM3 instructions                                                 |
| SM4          | SM4 instructions                                                 |
| SME                | AMD Secure Memory Encryption supported                                                                                                                                             |
| SME_COHERENT       | AMD Hardware cache coherency across encryption domains enforced                                                                                                                    |
| SPEC_CTRL_SSBD     | Speculative Store Bypass Disable                                                                                                                                                   |
| SRBDS_CTRL         | SRBDS mitigation MSR available                                                                                                                                                     |
| SSE                | SSE functions                                                                                                                                                                      |
| SSE2               | P4 SSE functions                                                                                                                                                                   |
| SSE3               | Prescott SSE3 functions                                                                                                                                                            |
| SSE4               | Penryn SSE4.1 functions                                                                                                                                                            |
| SSE42              | Nehalem SSE4.2 functions                                                                                                                                                           |
| SSE4A              | AMD Barcelona microarchitecture SSE4a instructions                                                                                                                                 |
| SSSE3              | Conroe SSSE3 functions                                                                                                                                                             |
| STIBP              | Single Thread Indirect Branch Predictors                                                                                                                                           |
| STIBP_ALWAYSON     | AMD: Single Thread Indirect Branch Prediction Mode has Enhanced Performance and may be left Always On                                                                              |
| STOSB_SHORT        | Fast short STOSB                                                                                                                                                                   |
| SUCCOR             | Software uncorrectable error containment and recovery capability.                                                                                                                  |
| SVE          | Scalable Vector Extension                                        |
| SVM                | AMD Secure Virtual Machine                                                                                                                                                         |
| SVMDA              | Indicates support for the SVM decode assists.                                                                                                                                      |
| SVMFBASID          | SVM, Indicates that TLB flush events, including CR3 writes and CR4.PGE toggles, flush only the current ASID's TLB entries. Also indicates support for the extended VMCBTLB_Control |
| SVML               | AMD SVM lock. Indicates support for SVM-Lock.                                                                                                                                      |
| SVMNP              | AMD SVM nested paging                                                                                                                                                              |
| SVMPF              | SVM pause intercept filter. Indicates support for the pause intercept filter                                                                                                       |
| SVMPFT             | SVM PAUSE filter threshold. Indicates support for the PAUSE filter cycle count threshold                                                                                           |
| SYSCALL            | System-Call Extension (SCE): SYSCALL and SYSRET instructions.                                                                                                                      |
| SYSEE              | SYSENTER and SYSEXIT instructions                                                                                                                                                  |
| Size     | Incremental | Full Buffer | Reset      | | Incremental Rate | Full Buffer Rate | Reset Rate   |
| Size     | Incremental | Full Buffer | Reset      | | Incremental Rate | Full Buffer Rate | Reset Rate  |
| Size   | Full Buffer |  Reset     | | Full Buffer Rate | Reset Rate   |
| TBM                | AMD Trailing Bit Manipulation                                                                                                                                                      |
| TDX_GUEST          | Intel Trust Domain Extensions Guest                                                                                                                                                |
| TLB_FLUSH_NESTED   | AMD: Flushing includes all the nested translations for guest translations                                                                                                          |
| TME                | Intel Total Memory Encryption. The following MSRs are supported: IA32_TME_CAPABILITY, IA32_TME_ACTIVATE, IA32_TME_EXCLUDE_MASK, and IA32_TME_EXCLUDE_BASE.                         |
| TOPEXT             | TopologyExtensions: topology extensions support. Indicates support for CPUID Fn8000_001D_EAX_x[N:0]-CPUID Fn8000_001E_EDX.                                                         |
| TSCRATEMSR         | MSR based TSC rate control. Indicates support for MSR TSC ratio MSRC000_0104                                                                                                       |
| TSXLDTRK           | Intel TSX Suspend Load Address Tracking                                                                                                                                            |
| USN Journals          | Windows                          | [Maybe](https://github.com/fsnotify/fsnotify/issues/53)                                                                         |
| VAES               | Vector AES. AVX(512) versions requires additional checks.                                                                                                                          |
| VMCBCLEAN          | VMCB clean bits. Indicates support for VMCB clean bits.                                                                                                                            |
| VMPL               | AMD VM Permission Levels supported                                                                                                                                                 |
| VMSA_REGPROT       | AMD VMSA Register Protection supported                                                                                                                                             |
| VMX                | Virtual Machine Extensions                                                                                                                                                         |
| VPCLMULQDQ         | Carry-Less Multiplication Quadword. Requires AVX for 3 register versions.                                                                                                          |
| VTE                | AMD Virtual Transparent Encryption supported                                                                                                                                       |
| WAITPKG            | TPAUSE, UMONITOR, UMWAIT                                                                                                                                                           |
| WBNOINVD           | Write Back and Do Not Invalidate Cache                                                                                                                                             |
| WRMSRNS            | Non-Serializing Write to Model Specific Register                                                                                                                                   |
| X87                | FPU                                                                                                                                                                                |
| XGETBV1            | Supports XGETBV with ECX = 1                                                                                                                                                       |
| XOP                | Bulldozer XOP functions                                                                                                                                                            |
| XSAVE              | XSAVE, XRESTOR, XSETBV, XGETBV                                                                                                                                                     |
| XSAVEC             | Supports XSAVEC and the compacted form of XRSTOR.                                                                                                                                  |
| XSAVEOPT           | XSAVEOPT available                                                                                                                                                                 |
| XSAVES             | Supports XSAVES/XRSTORS and IA32_XSS                                                                                                                                               |
| [nothing]        | ip=1234         |
| apex/log | 771 ns/op | +1124% | 5 allocs/op
| apex/log | 9068 ns/op | +13434% | 53 allocs/op
| apex/log | 9591 ns/op | +1362% | 63 allocs/op
| fanotify              | Linux 2.6.37+                    | [Planned](https://github.com/fsnotify/fsnotify/issues/114)                                                                      |
| go-kit | 213 ns/op | +238% | 9 allocs/op
| go-kit | 2249 ns/op | +243% | 57 allocs/op
| go-kit | 2460 ns/op | +3572% | 56 allocs/op
| inotify               | Linux 2.6.27 or later, Android\* | Supported |
| kqueue                | BSD, macOS, iOS\*                | Supported |
| log15 | 11393 ns/op | +1637% | 75 allocs/op
| log15 | 2069 ns/op | +3184% | 20 allocs/op
| log15 | 9038 ns/op | +13390% | 70 allocs/op
| logrus | 10521 ns/op | +15603% | 68 allocs/op
| logrus | 11654 ns/op | +1677% | 79 allocs/op
| logrus | 1439 ns/op | +2184% | 23 allocs/op
| slog (LogAttrs) | 200 ns/op | +199% | 0 allocs/op
| slog (LogAttrs) | 200 ns/op | +217% | 0 allocs/op
| slog (LogAttrs) | 2479 ns/op | +278% | 40 allocs/op
| slog | 193 ns/op | +188% | 0 allocs/op
| slog | 196 ns/op | +211% | 0 allocs/op
| slog | 2481 ns/op | +278% | 42 allocs/op
| standard library | 124 ns/op | +97% | 1 allocs/op
| zerolog | 32 ns/op | -49% | 0 allocs/op
| zerolog | 35 ns/op | -48% | 0 allocs/op
| zerolog | 380 ns/op | -42% | 1 allocs/op
|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|--------------|------------------------------------------------------------------|
|----------|-------------|-------------|------------|-|------------------|------------------|--------------|
|----------|-------------|-------------|------------|-|------------------|------------------|-------------|
|--------|-------------|------------|-|------------------|--------------|
}
}    
} else {
}()
})
}))
}).
