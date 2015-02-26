package main

import (
	"database/sql"
	"net/http"
	"html/template"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"
	//"io/ioutil"
	//"os"
	"code.google.com/p/go.crypto/bcrypt"
	"strconv"
	_ "github.com/lib/pq"
)

const TEMPLATEDIR string = "templates"
const MENUDIR string = "menu"
const LAYOUTPAGE string = TEMPLATEDIR + "/" + "layout.tmpl"
const LOGINPAGE string = TEMPLATEDIR + "/" + "login.tmpl"

type User struct {
	Name string
	Id string
}

func SetupDB() *sql.DB {
	db, err := sql.Open("postgres", "user=jallman password=abc dbname=webstruct_user host=localhost sslmode=disable")
	PanicIf(err)
	return db
}

func PanicIf(err error) {
	if err != nil {
	 panic(err)
	}
}

func main() {
	m := martini.Classic()

	// Sessions
	store := sessions.NewCookieStore([]byte("0l3CHNDWPLRwRG2TKoj0h3RsTCTpOExU"))
	m.Use(sessions.Sessions("webstruct",store))
	m.Map(SetupDB())

	m.Get("/logout", func(rw http.ResponseWriter, r *http.Request, s sessions.Session) {
	 //err := os.Remove(MENUDIR + "/" + s.Get("userId").(string))
	 //PanicIf(err)
	 s.Delete("userId")
	 http.Redirect(rw, r, "/login", http.StatusFound)
	})

	m.Get("/login", PostLogin)
	m.Post("/login", PostLogin)
	m.Post("/signup", Signup)

	m.Get("/", RequireLogin, PageLayout)
	m.Post("/", RequireLogin, PageLayout)
	m.Get("/go", RequireLogin, PageLayout)
	m.Post("/go", RequireLogin, PageLayout)


	m.Run()
}

func Signup(rw http.ResponseWriter, r *http.Request, db *sql.DB) {
	username, email, password := r.FormValue("username"), r.FormValue("email"), r.FormValue("password")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	PanicIf(err)
	_, err = db.Exec("insert into users (username,email,pass) values ($1, $2, $3)", username, email, hashedPassword)
	PanicIf(err)

	// redirect to login screen
	http.Redirect(rw, r, "/login", http.StatusFound)
}

func RequireLogin(rw http.ResponseWriter, req *http.Request, s sessions.Session, db *sql.DB, c martini.Context) {
	user := &User{}
	err := db.QueryRow("select uid, username from users where uid=$1", s.Get("userId")).Scan(&user.Id, &user.Name)

	if err != nil {
	 http.Redirect(rw, req, "/login", http.StatusFound)
	 return
	}

	// map the user to the context
	c.Map(user)

}

func PostLogin(rw http.ResponseWriter,w http.ResponseWriter, req *http.Request, db *sql.DB, s sessions.Session) {
	var id int 
	var pass string
	username, password := req.FormValue("USERNAME"), req.FormValue("PASSWD")

	if username == "" {
	  t, _ := template.ParseFiles(LOGINPAGE)
	  t.Execute(w,"")
	} else {
	  err := db.QueryRow("select uid, pass from users where username=$1", username).Scan(&id, &pass)
	  if err != nil || bcrypt.CompareHashAndPassword([]byte(pass), []byte(password)) != nil {
	   pageError := "Incorrect username or password"
	   t, _ := template.ParseFiles(LOGINPAGE)
	   t.Execute(w,&pageError)
	  } else {
	
	  s.Delete("userId")
	  s.Set("userId", id)
	
	  http.Redirect(rw, req, "/", http.StatusFound)
	  }
	}
}

/*
  ########################################################################################################################
  Below here we are building the page for authenticated users.
  The dynamic objects of the page are in 2 parts, the menu which is generated depending on what the user is allowed to do
  and the content generated when the user clicks on something
  ########################################################################################################################
*/

type Menu struct {
	//Type string
	ItemName string
	ItemScript string
}
var menuPage []Menu

type AuthPage struct {
	Body string
}
var bodyPage []AuthPage


func PageLayout(w http.ResponseWriter, r *http.Request, s sessions.Session, db *sql.DB, rw http.ResponseWriter, req *http.Request) {

	// Build the menu
	id := s.Get("userId").(int)
	PageMenu(id, db, rw, req)
	//PageContent(id, db, rw, req)

	//grab the script and build the content
	scr := req.FormValue("SCR")
	if scr == "" { scr="home" }

	switch scr {
	  case "profile":
	    wholePage := PageProfile(scr, id, db, rw, req, w)
	    wholePage.Menu = menuPage
            t, _ := template.ParseFiles(LAYOUTPAGE, wholePage.Content)
            t.Execute(w,wholePage)
	  default:
	    wholePage := *PageHome()
	    wholePage.Menu = menuPage
            t, _ := template.ParseFiles(LAYOUTPAGE, wholePage.Content)
            t.Execute(w,wholePage)
	}

}

//func PublishPage(st int) {
//	   wholePage.Menu = menuPage
//          t, _ := template.ParseFiles(LAYOUTPAGE, wholePage.Content)
//         t.Execute(w,wholePage)
//}



func PageMenu(id int, db *sql.DB, rw http.ResponseWriter, req *http.Request) {
	menuPage = nil

	var my_groups string
	allow_groups, err := db.Query("select gid from groupuser where uid=$1", id)
	PanicIf(err)
	for  allow_groups.Next() {
	  var gid string
	  allow_groups.Scan(&gid)
	  if my_groups == "" {
	    my_groups = "gid='" + gid + "'"
          } else {
	    my_groups = my_groups + " OR gid='" + gid  + "'"
          }
	 }

	if my_groups != "" {
	  allow_groups_inc, err := db.Query("select i.gid_inc from groupinc i,groupuser g where i.gid=g.gid and g.uid=$1;", id)
	  PanicIf(err)
	  for  allow_groups_inc.Next() {
	    var gid_inc string
	    allow_groups_inc.Scan(&gid_inc)
	    my_groups = my_groups + " OR gid='" + gid_inc  + "'"
	  }
	} else {
	  http.Redirect(rw, req, "/logout", http.StatusFound)
	}

	// Now that we have the groups we can retreive the user permissions
	var my_perms string
	my_groups = "select dirid,scr_all,scrid from groupauth where " + my_groups
	user_permissions, err := db.Query(my_groups)
	PanicIf(err)
	var get_menu string
	for user_permissions.Next() {
	  var dirid,scrid,scr_all string
	  user_permissions.Scan(&dirid,&scr_all,&scrid)
	  my_perms = my_perms + dirid + ", " + scr_all + ", " + scrid + "\n"

	  if scr_all == "true" {
	    if get_menu == "" {
	      get_menu = "d.dirid='" + dirid + "'"
	    } else {
	      get_menu = get_menu + " OR d.dirid='" + dirid + "'"
	    }
	  } else {
	    if get_menu == "" {
	      get_menu = "s.scrid='" + scrid + "'"
	    } else {
	      get_menu = get_menu + " OR s.scrid='" + scrid + "'"
	    }
	  }
	}
	
	grab_menu := ( "select d.name,d.menuname,s.name,s.menuname from dir d, script s where d.dirid=s.dirid AND ( " + get_menu + " ) order by d.shorder,s.shorder;\n" )
	build_the_menu, err := db.Query(grab_menu)
	PanicIf(err)
	var dirLast string
	for build_the_menu.Next() {
	  var dirName,dirMenuName,scriptName,scriptMenuName string
	  build_the_menu.Scan(&dirName,&dirMenuName,&scriptName,&scriptMenuName)
	  if dirName != dirLast {
	    menuPage = append(menuPage, Menu{dirMenuName,""}, )
	    dirLast = dirName
	  }
	menuPage = append(menuPage, Menu{scriptMenuName,scriptName}, )
	}
	return
}

/*
##################################################
### Here are some functions to check user input ##
##################################################
*/

/*
TESTING FROM HERE

type InputCheckData struct {
	Data string
	Name string
	Min int
	Max int
}

func (ic *InputCheckData) InputCheck() *string {
	var error string
	if len(ic.Data) > ic.Max {
	 error = "Your " + ic.Name + " is too long"
	}
	if len(ic.Data) < ic.Min {
	 error = "Your " + ic.Name + " is too short"
	}
	return &error
}
*/


type InputCheckData struct {
	Data string
	Name string
	Min int
	Max int
	Error *[]string
}
func (ic *InputCheckData) InputCheck() {
	var error string
	if len(ic.Data) > ic.Max {
	 error = "Your " + ic.Name + " is too long"
	}
	if len(ic.Data) < ic.Min {
	 error = "Your " + ic.Name + " is too short"
	}
	  *ic.Error = append(*ic.Error, error)
	return
}



/*
##################################
### We are building pages here ###
##################################
*/

//##################### Home

type HomePage struct {
	Menu []Menu
	Body string
	Content string
	Error []string
	Page string
}

func PageHome() *HomePage {
	homePage := new(HomePage)
	homePage.Body = "This is just a home page"
	homePage.Content = TEMPLATEDIR + "/home/index.html"
	homePage.Page = "index.html"
        return homePage
}


//##################### Profile

type ProfilePage struct {
	Scr string
	FirstName string
	LastName string
	Username string
	Email string
	Password string
}

type LoginPage struct {
	Menu []Menu
	Body ProfilePage
	Content string
	Error []string
}

func PageProfile(scr string, id int, db *sql.DB, rw http.ResponseWriter, r *http.Request, w http.ResponseWriter) *LoginPage {
	profilePage := new(ProfilePage)
	userData := new(ProfilePage)
	loginPage := new(LoginPage)
	profilePage.Scr = scr

	err := db.QueryRow("select firstname,lastname,username,email from users where uid=$1;", id).Scan(&profilePage.FirstName,&profilePage.LastName,&profilePage.Username,&profilePage.Email)
	PanicIf(err)
	
	dataReq := r.FormValue("SUBMIT")
	if dataReq == "Submit" {
	  userData.FirstName,userData.LastName,userData.Email = r.FormValue("FIRST_NAME"),r.FormValue("LAST_NAME"),r.FormValue("EMAIL")
	  // checkFirstName := InputCheckData{userData.FirstName, "First Name", 2, 32, &loginPage.Error}
	  InputCheckData{userData.FirstName, "First Name", 2, 32, &loginPage.Error}

	  //if *checkFirstName.InputCheck() != "" {
	  //loginPage.Error = append(loginPage.Error, *checkFirstName.InputCheck())
	  //}


	  //checkLastName := &InputCheckData{userData.LastName, "Last Name", 2, 32}
	  //loginPage.Error = append(loginPage.Error, *checkLastName.InputCheck())
	  //checkEmail := InputCheckData{userData.Email, "Email Address", 8, 64}
	  //loginPage.Error = append(loginPage.Error, *checkEmail.InputCheck())
	  
	    loginPage.Error = append(loginPage.Error, strconv.Itoa(len(loginPage.Error)))
	  if len(loginPage.Error) == 0 {
	    smt, err := db.Prepare("update users set firsname=? lastname=? email=?;")
	    PanicIf(err)
	    //err := db.Query("update users set firsname=$1 lastname=$2 email=$3;", userData.FirstName,userData.LastName,userData.Email)
	    _, err = smt.Exec(userData.FirstName,userData.LastName,userData.Email)
	    PanicIf(err)
	    
	  }
	}

	loginPage.Body = *profilePage
	loginPage.Content = TEMPLATEDIR + "/profile/index.html"

        return loginPage
}
