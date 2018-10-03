package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/julienschmidt/httprouter"
	uuid "github.com/satori/go.uuid"
)

type user struct {
	Username string
	Password []byte
	First    string
	Last     string
}

var tpl *template.Template
var dbUsers = map[string]user{}
var dbSessions = map[string]string{}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	bs, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	dbUsers["jamesbond"] = user{"jamesbond", bs, "James", "Bond"}
}

func main() {
	r := httprouter.New()
	r.GET("/", Index)
	r.GET("/signup", Signup)
	r.POST("/signup", Signup)
	r.GET("/login", Login)
	r.POST("/login", Login)
	r.GET("/home", Home)
	log.Fatal(http.ListenAndServe(":8080", r))
}

func Index(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	tpl.ExecuteTemplate(w, "index.html", nil)
}

func Signup(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/home", http.StatusSeeOther)
		return
	}

	if req.Method == "POST" {

		un := req.FormValue("username")
		p := req.FormValue("password")
		f := req.FormValue("firstname")
		l := req.FormValue("lastname")

		if _, ok := dbUsers[un]; ok {
			http.Error(w, "Sorry, username already taken!", http.StatusForbidden)
		}

		//create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)

		//persist in the database
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal Server Error ", http.StatusInternalServerError)
			return
		}

		u := user{un, bs, f, l}
		dbUsers[un] = u
		http.Redirect(w, req, "/", http.StatusSeeOther)
	}

	tpl.ExecuteTemplate(w, "signup.html", nil)
	fmt.Println(dbUsers)
}

//Login deals with how you login
func Login(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	//verify that their credentials match a user in the database.
	if req.Method == "POST" {
		un := req.FormValue("username")
		p := req.FormValue("password")

		//hash the password
		// bs, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		//get the stored hash from db and compare to input password
		//value is going to be the user object.
		if user, ok := dbUsers[un]; ok {
			//grab the password off the user object.
			hp := user.Password
			//bcrypt returns nil if the hashes match
			ok := bcrypt.CompareHashAndPassword(hp, []byte(p))
			if ok != nil {
				http.Error(w, "Incorrect credentials. Please try again.", http.StatusForbidden)
			}
			//if the passwords do match, then successfully login
			//1) add them to the session database
			// generate a new uuid and save that in the database.
			sID, _ := uuid.NewV4()
			c := &http.Cookie{
				Name:  "session",
				Value: sID.String(),
			}
			dbSessions[user.Username] = sID.String()
			fmt.Println(dbSessions)
			// write that uuid as a cookie on their browser.
			http.SetCookie(w, c)
			//2) redirect them home.

			http.Redirect(w, req, "/home", 302)
		} else {
			fmt.Println("user is: ", user)
			fmt.Println("userdb is: ", dbUsers)
			http.Error(w, "No account under that username — try signing up!", http.StatusForbidden)
		}

		return
	}
	//Assign them a session, and direct them to a login page.
	tpl.ExecuteTemplate(w, "login.html", nil)
}

func Home(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	tpl.ExecuteTemplate(w, "home.html", nil)
}
