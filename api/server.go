package main

import (
    "net/http"
    "time"
    "fmt"
    "sync"
    "strconv"
    "os"
    "io/ioutil"
    "encoding/json"
    
    "github.com/labstack/echo"

    "github.com/google/go-github/github"
    "golang.org/x/oauth2"
    githuboauth "golang.org/x/oauth2/github"

    "github.com/dgrijalva/jwt-go"
    "github.com/labstack/echo/middleware"
)

type UserInfo struct{
    ID int64 `json:"id"`
    Name string `json:"name"`
    Balance int64 `json:"balance"`
    History string `json:"history"`
}


var (
    // You must register the app at https://github.com/settings/developers
    // Set callback to http://127.0.0.1:7000/github_oauth_cb
    // Set ClientId and ClientSecret to
    oauthConf = &oauth2.Config{
        ClientID:     CONFIG_ClientID,
        ClientSecret: CONFIG_ClientSecret,
        Scopes:       []string{},
        Endpoint:     githuboauth.Endpoint,
    }
    // random string for oauth2 API calls to protect against CSRF
    oauthStateString = CONFIG_oauthStateString
    jwtSecret = CONFIG_jwtSecret
    coinsUrl = CONFIG_coinsUrl
    adminID = int64(CONFIG_adminID)
    lock  sync.Mutex
    data  map[int64]*UserInfo
    timeformat = "2006-01-02 15:04:05"
)

// /login
func handleGitHubLogin(c echo.Context) error {
    url := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)
    return c.Redirect(http.StatusTemporaryRedirect, url)
}

// /github_oauth_cb
func handleGitHubCallback(c echo.Context) error {
    state := c.FormValue("state")
    if state != oauthStateString {
        return c.Redirect(http.StatusTemporaryRedirect, coinsUrl+"?error=OAuthFailed.1")
    }

    code := c.FormValue("code")
    token, err := oauthConf.Exchange(oauth2.NoContext, code)
    if err != nil {
        return c.Redirect(http.StatusTemporaryRedirect, coinsUrl+"?error=OAuthFailed.2")
    }

    oauthClient := oauthConf.Client(oauth2.NoContext, token)
    client := github.NewClient(oauthClient)
    user, _, err := client.Users.Get(oauth2.NoContext, "")
    if err != nil {
        return c.Redirect(http.StatusTemporaryRedirect, coinsUrl+"?error=OAuthFailed.3")
    }
    fmt.Printf("Logged in as GitHub user: %s\n", *user.Login)

    jwtToken := jwt.New(jwt.SigningMethodHS256)

    // Set claims
    claims := jwtToken.Claims.(jwt.MapClaims)
    claims["name"] = *user.Login
    claims["id"] = *user.ID
    claims["exp"] = time.Now().Add(time.Hour).Unix()

    // Generate encoded token and send it as response.
    t, err := jwtToken.SignedString([]byte(jwtSecret))
    if err != nil {
        return err
    }
    return c.Redirect(http.StatusTemporaryRedirect, coinsUrl+"?token="+t)
}

func loadInfo(id int64) bool{
    path := fmt.Sprintf("./data/coins-%d.json", id)
    _, err := os.Stat(path)
    if err != nil{
        return false
    }
    bytes, err := ioutil.ReadFile(path)
    if err != nil{
        panic(err)
    }
    info := &UserInfo{}
    err = json.Unmarshal(bytes, info)
    if err != nil{
        panic(err)
    }
    data[id]= info
    return true
}
func dumpInfo(id int64) {
    path := fmt.Sprintf("./data/coins-%d.json", id)
    bytes, err := json.Marshal(data[id])
    if err != nil{
        panic(err)
    }
    err = ioutil.WriteFile(path, bytes, 0644)
    if err!=nil{
        panic(err)
    }
}

func getInfo(c echo.Context) error{
    token := c.Get("user").(*jwt.Token)
    claims := token.Claims.(jwt.MapClaims)
    name := claims["name"].(string)
    id := int64(claims["id"].(float64))
    lock.Lock()
    defer lock.Unlock()
    info, ok := data[id]
    if !ok{
        ok := loadInfo(id)
        if !ok{
            info = &UserInfo{
                ID: id,
                Name: name,
                Balance: 0,
                History: time.Now().Format(timeformat)+" Create Account\n",
            }
            data[id] = info
            dumpInfo(id)
        }else{
            info = data[id]
        }
    }
    info.Name = name

    return c.JSON(http.StatusOK, map[string]string{
        "result": "ok",
        "name": name,
        "id": strconv.FormatInt(id, 10),
        "balance": strconv.FormatInt(info.Balance,10),
        "history": info.History,
        "global-sum": strconv.FormatInt(-data[adminID].Balance,10),
    })
}

func transfer(c echo.Context) error{
    token := c.Get("user").(*jwt.Token)
    claims := token.Claims.(jwt.MapClaims)
    name := claims["name"].(string)
    id := int64(claims["id"].(float64))
    
    toid, err := strconv.ParseInt(c.FormValue("githubid"), 10, 64)
    if err != nil {
        return c.JSON(http.StatusOK, map[string]string{
            "result": "failed",
            "detail": "github id parse failed",
        })
    }
    amount, err := strconv.ParseInt(c.FormValue("amount"), 10, 64)
    if err != nil {
        return c.JSON(http.StatusOK, map[string]string{
            "result": "failed",
            "detail": "amount parse failed",
        })
    }
    if amount <= 0{
        return c.JSON(http.StatusOK, map[string]string{
            "result": "failed",
            "detail": "amount <= 0",
        })
    }

    lock.Lock()
    defer lock.Unlock()

    toinfo, ok := data[toid]
    if !ok{
        ok = loadInfo(toid)
        if !ok{
            return c.JSON(http.StatusOK, map[string]string{
                "result": "failed",
                "detail": "github id not found",
            })
        }else{
            toinfo = data[toid]
        }
        
    }

    info, ok := data[id]
    if !ok{
        ok := loadInfo(id)
        if !ok{
            info = &UserInfo{
                ID: id,
                Name: name,
                Balance: 0,
                History: time.Now().Format(timeformat)+" Create Account\n",
            }
            data[id] = info
        }else{
            info = data[id]
        }
    }

    if amount > info.Balance && id != adminID{
        return c.JSON(http.StatusOK, map[string]string{
            "result": "failed",
            "detail": "amount > balance",
        })
    }

    // do transfer
    info.Balance = info.Balance - amount
    toinfo.Balance = toinfo.Balance + amount
    msg := fmt.Sprintf(time.Now().Format(timeformat)+" %s(%d) -> %s(%d) : %d\n", info.Name, info.ID, toinfo.Name, toinfo.ID, amount)
    info.History = msg + info.History
    if len(info.History) > 2000{
        info.History = string(info.History[:2000])+"..."
    }
    toinfo.History = msg + info.History
    if len(toinfo.History) > 2000{
        toinfo.History = string(toinfo.History[:2000])+"..."
    }
    dumpInfo(id)
    dumpInfo(toid)
    return c.JSON(http.StatusOK, map[string]string{
        "result": "ok",
        "detail": msg,
    })
}

func touchDir(path string){
    fileInfo, err := os.Stat(path)
    if os.IsNotExist(err)  {
        os.Mkdir(path,0755)
    }else if err != nil{
        panic(err)
    }else if ! fileInfo.IsDir(){
        panic(fmt.Errorf("path %s is not dir", path))
    }
}

func main() {
    data  = make(map[int64]*UserInfo)
    touchDir("./data/")
    e := echo.New()

    e.GET("/login", handleGitHubLogin)
    e.GET("/github_oauth_cb", handleGitHubCallback)
    e.GET("/", func(c echo.Context) error {
        return c.String(http.StatusOK, "ok")
    })

    // Restricted group
    r := e.Group("/coins")
    r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
      SigningKey: []byte(jwtSecret),
      TokenLookup: "query:token",
    }))
    r.GET("/info", getInfo)
    r.POST("/transfer", transfer)

    e.Logger.Fatal(e.Start("127.0.0.1:7000"))
}
