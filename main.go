package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	SESSION_TTL        = 1 * time.Hour
	COOKIE_SESSION_KEY = "session"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/item/guest", guestItemHandler)
	http.HandleFunc("/item/common", commonItemHandler)
	http.HandleFunc("/item/admin", adminItemHandler)

	log.Fatal(http.ListenAndServe(":3000", nil))
}

func bindRequest(r *http.Request, dest any) error {
	length, err := strconv.Atoi(r.Header.Get("Content-Length"))
	if err != nil {
		return err
	}

	body := make([]byte, length)
	length, err = r.Body.Read(body)
	if err != nil && err != io.EOF {
		return err
	}

	if err = json.Unmarshal(body[:length], dest); err != nil {
		return err
	}

	return nil
}

func can(demand []Role, have []Role) error {
	hash := map[Role]interface{}{}
	for _, v := range demand {
		hash[v] = struct{}{}
	}

	for _, v := range have {
		if _, ok := hash[v]; ok {
			return nil
		}
	}
	return errors.New("The user does not have permission")
}

func decodeToken(r *http.Request) (*AuthInfo, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, fmt.Errorf("Cannot get cookie: %w", err)
	}

	tokenString := cookie.Value
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid token: Unexpected signing method %v", t.Header["alg"])
		}
		return []byte(SECRET), nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Invalid token: Failed to parse claims")
	}

	if !token.Valid {
		return nil, errors.New("Invalid token: Invalid format")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("Invalid token: Invalid exp format")
	}

	rolesClaim, ok := claims["roles"].([]interface{})
	if !ok {
		return nil, errors.New("Invalid token: Invalid roles format")
	}

	var roles []Role
	for _, v := range rolesClaim {
		roles = append(roles, interpretRole(v))
	}

	a := &AuthInfo{
		UserID: claims["user_id"].(string),
		Roles:  roles,
		Exp:    time.Unix(0, int64(exp)),
	}

	return a, nil
}

func itemHandler(w http.ResponseWriter, r *http.Request) {}

type loginRequestParams struct {
	UserID string `json:"user_id"`
	Passwd string `json:"password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var b loginRequestParams
		if err := bindRequest(r, &b); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, ok := userGroupMapping[b.UserID]; !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if b.Passwd == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		a := AuthInfo{
			UserID: b.UserID,
			Roles:  userRoleMapping[b.UserID],
			Exp:    time.Now().Add(SESSION_TTL),
		}

		ts, err := a.Token()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     COOKIE_SESSION_KEY,
			Value:    ts,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func guestItemHandler(w http.ResponseWriter, r *http.Request) {
	a, err := decodeToken(r)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
	}

	if err := can([]Role{RoleGuest}, a.Roles); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	json, err := json.Marshal(a)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func commonItemHandler(w http.ResponseWriter, r *http.Request) {
	a, err := decodeToken(r)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
	}

	if err := can([]Role{RoleCommonn}, a.Roles); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	json, err := json.Marshal(a)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func adminItemHandler(w http.ResponseWriter, r *http.Request) {
	a, err := decodeToken(r)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
	}

	if err := can([]Role{RoleAdmin}, a.Roles); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	json, err := json.Marshal(a)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var jsonBody map[string]interface{}
		if err := bindRequest(r, &jsonBody); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
