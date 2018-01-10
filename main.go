package main

// Google part: https://skarlso.github.io/2016/06/12/google-signin-with-go/

import (
	"net/http"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"golang.org/x/oauth2"
	"os"
	"golang.org/x/oauth2/facebook"
	"fmt"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/net/context"
	"encoding/json"
	"strconv"
	"golang.org/x/oauth2/github"
)

var (
	facebookOAuthConfig = &oauth2.Config{
		RedirectURL: "http://localhost:3300/FacebookCallback",
		ClientID: "717098951814338",
		ClientSecret: "ca9302f587883824eacb3c7631b1ca70",
		Scopes: []string{"email"},
		Endpoint: facebook.Endpoint,
	}
	githubOAuthConfig = &oauth2.Config{
		RedirectURL: "http://localhost:3300/GithubCallback",
		ClientID: "c105a3783f1848a5ee78",
		ClientSecret: "98208c5de3c8d48df25dfdac420c59176bf512b4",
		Scopes: []string{
			"user:email",
			"repo",
		},
		Endpoint: github.Endpoint,
	}
	googleOAuthConfig = &oauth2.Config{
		RedirectURL: "http://localhost:3300/GoogleCallback",
		ClientID: "247723072774-92vovudfpnae8sr77b4jiajrfq9lchac.apps.googleusercontent.com",
		ClientSecret: "u0l_3id0zQpCPkj8deoc-78O",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	oauthStateString = "veryrandom"

)

type GoogleUser struct {
	Name string `json:"name"`
	Id string `json:"id"`
	Email string `json:"email"`
	Picture string `json:"picture"`
	Locale string `json:"locale"`
}

type GithubUser struct {
	Username string `json:"login"`
	Name string `json:"name"`
	Id int `json:"id"`
	Picture string `json:"avatar_url"`
	ReposNo int `json:"public_repos"`
}

func main() {
	// instantiate the gorilla/mux router
	r := mux.NewRouter()

	// the default route handler is just the hello handler
	r.Handle("/", IndexHandler).Methods("GET")

	r.Handle("/GoogleLogin", GoogleLoginHandler).Methods("GET")
	r.Handle("/GoogleCallback", GoogleCallbackHandler).Methods("GET")

	r.Handle("/GithubLogin", GithubLoginHandler).Methods("GET")
	r.Handle("/GithubCallback", GithubCallbackHandler).Methods("GET")

	r.Handle("/FacebookLogin", FacebookLoginHandler).Methods("GET")
	r.Handle("/FacebookCallback", FacebookCallbackHandler).Methods("GET")

	http.ListenAndServe(":3300", handlers.LoggingHandler(os.Stdout, r))
}

var IndexHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	const HtmlIndex = `<html><body>
	<div><a href="/FacebookLogin">Log in with Facebook</a></div>
	<div><a href="/GoogleLogin">Log in with Google</a></div>
	<div><a href="/GithubLogin">Log in with Github</a></div>
	</body></html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(HtmlIndex))
})

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func generateNewOAuthState() string {
	oauthStateString = randToken()

	return oauthStateString
}

func GetGoogleUserFromJSON(body []byte) (*GoogleUser, error) {
	var s = new(GoogleUser)
	err := json.Unmarshal(body, &s)

	if err != nil {
		fmt.Println("Failed to unmarshal JSON:", err)
	}

	return s, err
}

func GetGithubUserFromJSON(body []byte) (*GithubUser, error) {
	var s = new(GithubUser)
	err := json.Unmarshal(body, &s)

	if err != nil {
		fmt.Println("Failed to unmarshal JSON:", err)
	}

	return s, err
}

var GoogleLoginHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	url := googleOAuthConfig.AuthCodeURL(generateNewOAuthState())
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
})

var GoogleCallbackHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")

	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Println("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)

	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)

	if err != nil {
		fmt.Println("Failed to read response body", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// parse the JSON response to a user object
	var loggedInUser, error = GetGoogleUserFromJSON(contents)

	if error != nil {
		fmt.Println("Failed to parse JSON", error)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var loggedInResponse = `<html><body>
	<div><b>User: </b>` + loggedInUser.Name + `</div>
	<div><b>Id: </b>` + loggedInUser.Id + `</div>
	<div><b>Email: </b>` + loggedInUser.Email + `</div>
	<div><b>Locale: </b>` + loggedInUser.Locale + `</div>
	<div><img src="` + loggedInUser.Picture + `" width="80" height="80" /></div>
	`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(loggedInResponse))
})

var GithubLoginHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	url := githubOAuthConfig.AuthCodeURL(generateNewOAuthState())
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
})

var GithubCallbackHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")

	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := githubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Println("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	response, err := http.Get("https://api.github.com/user?access_token=" + token.AccessToken)

	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)

	if err != nil {
		fmt.Println("Failed to read response body", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// parse the JSON response to a user object
	loggedInUser, err := GetGithubUserFromJSON(contents)

	if err != nil {
		fmt.Println("Failed to parse JSON", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var loggedInResponse = `<html><body>
	<div><b>User: </b>` + loggedInUser.Username + `</div>
	<div><b>Full name: </b>` + loggedInUser.Name + `</div>
	<div><b>Id: </b>` + strconv.Itoa(loggedInUser.Id) + `</div>
	<div><b>Public repos: </b>` + strconv.Itoa(loggedInUser.ReposNo) + `</div>
	<div><img src="` + loggedInUser.Picture + `" width="92" height="92" /></div>
	`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(loggedInResponse))
})

var FacebookLoginHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	url := facebookOAuthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
})

var FacebookCallbackHandler = http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")

	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := facebookOAuthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Println("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	/*response, err := http.Get("https://graph.facebook.com/v2.10/oauth/access_token?client_id=" + facebookOAuthConfig.ClientID + "&redirect_uri=" + facebookOAuthConfig.RedirectURL + "&client_secret=" + facebookOAuthConfig.ClientSecret + "&code=" + code)

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)*/
	fmt.Fprintf(w, "Token: %s\n", token)
})