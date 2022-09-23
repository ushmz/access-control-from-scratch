package main

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	SECRET = "dummy"
)

type Group int

const (
	GroupAdmin Group = iota + 1
	GroupCommon
	GroupGuest
)

type Role int

const (
	RoleAdmin Role = iota + 1
	RoleCommonn
	RoleItems
	RoleGuest
)

func interpretRole(val interface{}) Role {
	switch val.(type) {
	case float64:
		switch val.(float64) {
		case float64(1):
			return RoleAdmin
		case float64(2):
			return RoleCommonn
		case float64(3):
			return RoleItems
		case float64(4):
			return RoleGuest
		default:
			return 0
		}
	case int64:
		switch val.(int64) {
		case int64(1):
			return RoleAdmin
		case int64(2):
			return RoleCommonn
		case int64(3):
			return RoleItems
		case int64(4):
			return RoleGuest
		default:
			return 0
		}
	default:
		return 0
	}
}

var userGroupMapping = map[string]Group{
	"admin":      GroupAdmin,
	"smakethorn": GroupCommon,
	"coituscent": GroupGuest,
}

var userRoleMapping = map[string][]Role{
	"admin":      {RoleAdmin, RoleCommonn, RoleGuest},
	"smakethorn": {RoleCommonn, RoleGuest},
	"coituscent": {RoleGuest},
}

type AuthInfo struct {
	UserID string    `json:"user_id"`
	Roles  []Role    `json:"roles"`
	Exp    time.Time `json:"exp"`
}

func (a *AuthInfo) Token() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": a.UserID,
		"roles":   a.Roles,
		"exp":     a.Exp.UnixNano(),
	})

	return token.SignedString([]byte(SECRET))
}
