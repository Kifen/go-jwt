package common

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"strings"
)

func ValidateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token []string
		bearer := r.Header.Get("Authorization")
		if bearer != "" {
			if strings.ToUpper(bearer[0:6]) == "BEARER" {
				token = strings.Split(bearer, " ")
			} else {
				fmt.Fprint(w, http.StatusInternalServerError)
			}

			tokenString, err := jwt.Parse(token[1], func(tokenString *jwt.Token) (i interface{}, e error) {
				if _, ok := tokenString.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", tokenString.Header["alg"])
				}
				return []byte(JwtSecret), nil
			})

			if err != nil {
				json.NewEncoder(w).Encode(err)
				log.Println(err)
				return
			}

			if claims, ok := tokenString.Claims.(jwt.MapClaims); ok && tokenString.Valid {
				email := claims["name"]
				ctx := context.WithValue(r.Context(), "email", email)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
}

func RefreshTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	var refresh_token string
	var cred *Credentials

	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		refresh_token = request.Header.Get("refresh_token")
		client_id := request.Header.Get("client_id")
		client_secret := request.Header.Get("client_secret")
		cred = &Credentials{Email: client_id, Password: client_secret}

		if refresh_token == "" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(refresh_token, func(token *jwt.Token) (i interface{}, e error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(JwtSecret), nil
		})

		if err != nil {
			json.NewEncoder(writer).Encode(err)
			log.Println(err)
			return
		}

		if token.Valid {
			ctx := context.WithValue(request.Context(), "credentials", cred)
			next.ServeHTTP(writer, request.WithContext(ctx))
			return
		} else {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
}
