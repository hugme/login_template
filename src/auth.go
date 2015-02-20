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
        //"strconv"
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
        db, err := sql.Open("postgres", "user=dbuser password=abc dbname=webstruct_user host=localhost sslmode=disable")
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
	// the store key needs to be replaced with a pointer to a config file
        store := sessions.NewCookieStore([]byte("replacethis123"))
        m.Use(sessions.Sessions("webstruct",store))
        m.Map(SetupDB())

        m.Get("/logout", func(rw http.ResponseWriter, r *http.Request, s sessions.Session) {
         //err := os.Remove(MENUDIR + "/" + s.Get("userId").(string))
         //PanicIf(err)
         s.Delete("userId")
         http.Redirect(rw, r, "/login", http.StatusFound)
        })

        m.Get("/", RequireLogin, PageLayout)
        m.Post("/", RequireLogin, PageLayout)
        m.Get("/login", PostLogin)
        m.Post("/login", PostLogin)

        // Signup needs to be moved into "/" as a script
        m.Post("/signup", Signup)

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


func PageLayout(w http.ResponseWriter, r *http.Request, s sessions.Session, db *sql.DB, rw http.ResponseWriter, req *http.Request) {

        id := s.Get("userId").(int)
        PageMenu(id, db, rw, req)
        bodyPage := []AuthPage{{"a"},{"b"},{"c"}}

        t, _ := template.ParseFiles(LAYOUTPAGE)
        t.Execute(w,struct{
         ASlice []Menu
         BSlice []AuthPage
        }{
         ASlice: menuPage,
         BSlice: bodyPage,
        })
}

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
          menuPage = append(menuPage, Menu{scriptName,scriptMenuName}, )

          }
        }

        return
}

//func PageContent(title string) (*Page, error){
//      filename := title + ".txt"
//      body, err := ioutil.ReadFile(filename)
//      if err != nil {
//       return nil, err
//      }
//      return &Page{Title: title, Body: body}, nil
//}
