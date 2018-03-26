package api

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"net/mail"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/ansible-semaphore/semaphore/db"
	"github.com/ansible-semaphore/semaphore/util"
	"github.com/castawaylabs/mulekick"
	"github.com/gorilla/context"
	sq "github.com/masterminds/squirrel"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ldap.v2"
)

func findLDAPUser(username, password string) (*db.User, error) {
	if util.Config.LdapEnable != true {
		return nil, fmt.Errorf("LDAP not configured")
	}

	l, err := ldap.Dial("tcp", util.Config.LdapServer)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	// Reconnect with TLS if needed
	if util.Config.LdapNeedTLS == true {
		// TODO: InsecureSkipVerify should be configurable
		tlsConf := tls.Config{
			InsecureSkipVerify: true,
		}
		if err := l.StartTLS(&tlsConf); err != nil {
			return nil, err
		}
	}

	// First bind with a read only user
	if err := l.Bind(util.Config.LdapBindDN, util.Config.LdapBindPassword); err != nil {
		return nil, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		util.Config.LdapSearchDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(util.Config.LdapSearchFilter, username),
		[]string{util.Config.LdapMappings.DN},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) != 1 {
		return nil, fmt.Errorf("User does not exist or too many entries returned")
	}

	// Bind as the user to verify their password
	userdn := sr.Entries[0].DN
	if err := l.Bind(userdn, password); err != nil {
		return nil, err
	}

	// Get user info and ensure authentication in case LDAP supports unauthenticated bind
	searchRequest = ldap.NewSearchRequest(
		util.Config.LdapSearchDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(util.Config.LdapSearchFilter, username),
		[]string{util.Config.LdapMappings.DN, util.Config.LdapMappings.Mail, util.Config.LdapMappings.Uid, util.Config.LdapMappings.CN},
		nil,
	)

	sr, err = l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	ldapUser := db.User{
		Username: sr.Entries[0].GetAttributeValue(util.Config.LdapMappings.Uid),
		Created:  time.Now(),
		Name:     sr.Entries[0].GetAttributeValue(util.Config.LdapMappings.CN),
		Email:    sr.Entries[0].GetAttributeValue(util.Config.LdapMappings.Mail),
		External: true,
		Alert:    false,
	}

	log.Info("User " + ldapUser.Name + " with email " + ldapUser.Email + " authorized via LDAP correctly")
	return &ldapUser, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var login struct {
		Auth     string `json:"auth" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := mulekick.Bind(w, r, &login); err != nil {
		return
	}

	/*
		logic:
		- fetch user from ldap if enabled
		- fetch user from database by username/email
		- create user in database if doesn't exist & ldap record found
		- check password if non-ldap user
		- create session & send cookie
	*/

	login.Auth = strings.ToLower(login.Auth)

	var ldapUser *db.User
	if util.Config.LdapEnable {
		// search LDAP for users
		if lu, err := findLDAPUser(login.Auth, login.Password); err == nil {
			ldapUser = lu
		} else {
			log.Info(err.Error())
		}
	}

	var user db.User
	q := sq.Select("*").
		From("user")

	// determine if login.Auth is email or username
	if _, err := mail.ParseAddress(login.Auth); err == nil {
		q = q.Where("email=?", login.Auth)
	} else {
		q = q.Where("username=?", login.Auth)
	}

	query, args, _ := q.ToSql()
	if err := db.Mysql.SelectOne(&user, query, args...); err != nil && err == sql.ErrNoRows {
		if ldapUser != nil {
			// create new LDAP user
			user = *ldapUser
			if err := db.Mysql.Insert(&user); err != nil {
				panic(err)
			}
		} else {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else if err != nil {
		panic(err)
	}

	// check if ldap user & no ldap user found
	if user.External && ldapUser == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// non-ldap login
	if !user.External {
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password)); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// authenticated.
	}

	session := db.Session{
		UserID:     user.ID,
		Created:    time.Now(),
		LastActive: time.Now(),
		IP:         r.Header.Get("X-Real-IP"),
		UserAgent:  r.Header.Get("user-agent"),
		Expired:    false,
	}
	if err := db.Mysql.Insert(&session); err != nil {
		panic(err)
	}

	encoded, err := util.Cookie.Encode("semaphore", map[string]interface{}{
		"user":    user.ID,
		"session": session.ID,
	})
	if err != nil {
		panic(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "semaphore",
		Value: encoded,
		Path:  "/",
	})

	w.WriteHeader(http.StatusNoContent)
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:  "semaphore",
		Value: "",
		//Expires: time.Now().Add(24 * 7 * time.Hour * -1),
		Path: "/",
	})

	w.WriteHeader(http.StatusNoContent)
}

func totp_isbind(w http.ResponseWriter, r *http.Request) {
	if userID, exists := context.GetOk(r, "userID"); exists {

		u, err := db.FetchUser(userID.(int))

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		isbind := (u.TotpKey.String != "")

		//generate totp image
		var imgBase64Str = ""
		if !isbind {
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "deploy",
				AccountName: u.Name,
			})
			if err != nil {
				panic(err)
			}
			img, err := key.Image(200, 200)
			var buf bytes.Buffer
			png.Encode(&buf, img)
			imgBase64Str = base64.StdEncoding.EncodeToString(buf.Bytes())
			//update user totp key
			if _, err := db.Mysql.Exec("update user set totp_key=? where id=?", key.Secret(), userID); err != nil {
				panic(err)
			}
		}
		d := map[string]interface{}{
			"isbind":        isbind,
			"base64_qrcode": imgBase64Str,
		}

		mulekick.WriteJSON(w, http.StatusOK, d)
		return
	} else {
		w.WriteHeader(http.StatusForbidden)
		return
	}
}

func totp_verify(w http.ResponseWriter, r *http.Request) {
	userID, exists := context.GetOk(r, "userID")
	if !exists {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sessionID, exists := context.GetOk(r, "sessionID")
	if !exists {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u, err := db.FetchUser(userID.(int))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var code struct {
		VerifyCode string `json:"verify_code"`
	}
	if err := mulekick.Bind(w, r, &code); err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	verify_code := code.VerifyCode
	valid := totp.Validate(verify_code, u.TotpKey.String)
	db.UpdateSession(sessionID.(int), userID.(int), "session_valid_totp", valid)

	fmt.Printf("code:%v key:%v valid:%v\n", verify_code, u.TotpKey.String, valid)

	d := map[string]interface{}{
		"success": valid,
	}
	mulekick.WriteJSON(w, http.StatusOK, d)
}
