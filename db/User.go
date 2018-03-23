package db

import (
	"time"
	"database/sql"
)

type User struct {
	ID       int       `db:"id" json:"id"`
	Created  time.Time `db:"created" json:"created"`
	Username string    `db:"username" json:"username" binding:"required"`
	Name     string    `db:"name" json:"name" binding:"required"`
	Email    string    `db:"email" json:"email" binding:"required"`
	Password string    `db:"password" json:"-"`
	Admin    bool      `db:"admin" json:"admin"`
	External bool      `db:"external" json:"external"`
	Alert    bool      `db:"alert" json:"alert"`
	TotpKey    sql.NullString      `db:"totp_key" json:"-"`
}

func FetchUser(userID int) (*User, error) {
	var user User

	err := Mysql.SelectOne(&user, "select * from user where id=?", userID)
	return &user, err
}
