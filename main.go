package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

var log *zap.SugaredLogger
var clientSecret string
var clientID string
var scope string
var redirectURI string
var client *http.Client

func init() {
	// create our HTTP client
	client = &http.Client{}

	// configure logging
	logger, _ := zap.NewDevelopment()
	defer logger.Sync() // flushes buffer, if any
	log = logger.Sugar()

	// set up the azure connection credentials
	clientSecret = "6I-qGSo4FU4TBgMCR8_Ds.xV3hZj-~uRcf"
	clientID = "78f1ffae-efc3-4dae-9058-6e1eb8d18ae0"

	// pre-uri encoded scopes fails with consent error AADSTS65001
	// uncomment this to fail
	// scope = "openid%20offline_access%20https%3A%2F%2Fgraph.microsoft.com%2Fmail.read%20https%3A%2F%2Fgraph.microsoft.com%2Fmail.send"

	// space separated string with scopes is fine
	// uncomment this to pass
	scope = "openid offline_access mail.read mail.send"

	// I just realized I haven't been uri encoding the reply URI and if I do pre-encode it I get an error here too
	redirectURI = "http://localhost:5000/callback"
}

func main() {
	startServer()
}
// startServer spins up an http listener for this service on the
// port and path specified
func startServer() {
	// define the new router, define paths, and handlers on the router
	router := mux.NewRouter().StrictSlash(true)

	// set the routes on our api
	router.HandleFunc("/request", redirect)
	router.HandleFunc("/callback", callback)

	// start the server
	log.Info("New server started")
	log.Fatal(http.ListenAndServe(":5000", router))
}

// redirect takes an incoming request and redirects it to the authorize endpoint at Azure
func redirect(w http.ResponseWriter, r *http.Request) {
	log.Info("Incoming redirect request")

	// authorization endpoint to redirect the user to
	endpoint := "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" +
	fmt.Sprintf("client_id=%v", clientID) +
	"&response_type=code" +
	fmt.Sprintf("&redirect_uri=%v", redirectURI) +
	"&response_mode=query" +
	fmt.Sprintf("&scope=%v", scope) +
	"&state=12345"

	log.Infof("Authorize endpoint: %v", endpoint)

	// redirect the user to the Azure endpoint
	http.Redirect(w, r, endpoint, 302)

	// implicit return here to prevent any writes to the response
	return
}

// callback receives a POST from Azure after a successful authorization request with an authorization code we can use
// to retrieve an access token from Azure
func callback(w http.ResponseWriter, r *http.Request) {
	log.Info("Callback from Azure received")

	// check and make sure we have a code on the incoming post
	codeCheck, ok := r.URL.Query()["code"]
	if !ok {
		// no code on the request so we have to return early
		log.Info("No code on request")
		w.WriteHeader(401)
		return
	}

	// pull the authorization code off the incoming post
	code := codeCheck[0]

	// endpoint for the Azure token api we post to
	endpoint := "https://login.microsoftonline.com/common/oauth2/v2.0/token"

	log.Infof("Token endpoint: %v", endpoint)

	// build the params since we need to post a urlencoded form
	params := url.Values{
		"client_id": {clientID},
		"scope": {scope},
		"code": {code},
		"redirect_uri": {redirectURI},
		"client_secret": {clientSecret},
		"grant_type": {"authorization_code"},
	}

	// create the actual request but don't make it yet
	post, err := http.NewRequest("POST", endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		// something went wrong for some reason internally to the HTTP package
		log.Errorf("could not create POST request for token retrieval: %v", err)
		w.WriteHeader(500)
		return
	}

	// set the headers on the outgoing request
	post.Header.Set("Accept", "application/json")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")


	// actually make the request
	resp, err := client.Do(post)
	if err != nil {
		log.Errorf("couldn't make POST request to Azure: %v", err)
		w.WriteHeader(500)
		return
	}

	// just read out the request for demo purposes
	defer resp.Body.Close()
	respBytes, _ := ioutil.ReadAll(resp.Body)

	log.Infof("Response from Azure: %v", string(respBytes))

	// write the response back to the request
	w.WriteHeader(200)
	w.Write(respBytes)

	// implicit return to prevent further writes
	return
}
