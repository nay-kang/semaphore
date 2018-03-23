package db

import (
	"encoding/json"
	// "fmt"
	"time"
)

type Session struct {
	ID         int                    `db:"id" json:"id"`
	UserID     int                    `db:"user_id" json:"user_id"`
	Created    time.Time              `db:"created" json:"created"`
	LastActive time.Time              `db:"last_active" json:"last_active"`
	IP         string                 `db:"ip" json:"ip"`
	UserAgent  string                 `db:"user_agent" json:"user_agent"`
	Expired    bool                   `db:"expired" json:"expired"`
	DataRaw    string                 `db:"data" json:"-"`
	Data       map[string]interface{} `db:"-"`
}

func FetchSession(sessionID int, userID int) (*Session, error) {
	var session Session

	err := Mysql.SelectOne(&session, "select * from session where id=? and user_id=? and expired=0", sessionID, userID)

	if err != nil {
		return nil, err
	}
	if session.DataRaw != "" {
		err = json.Unmarshal([]byte(session.DataRaw), &(session.Data))
	}

	return &session, err
}

func UpdateSession(sessionID int, userID int, key string, val interface{}) {
	session, err := FetchSession(sessionID, userID)
	if err != nil {
		panic(err)
	}
	data := session.Data
	if data == nil {
		data = make(map[string]interface{})
	}
	data[key] = val
	json_data, _ := json.Marshal(data)
	if _, err := Mysql.Exec("update session set data=? where id=? and user_id=?", json_data, sessionID, userID); err != nil {
		panic(err)
	}
}
