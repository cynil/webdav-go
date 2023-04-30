package lib

import (
	"golang.org/x/net/webdav"
)


type Share struct {
	// zlj
	Name     string
	Scope    string
	Users    map[string]*User
	Handler  *webdav.Handler 
}

// User contains the settings of each user.
type User struct {
	// zlj
	Username string
	Password string
	Modify   bool
}

func (u User) Allowed(noModification bool) bool {
	return noModification || u.Modify
}