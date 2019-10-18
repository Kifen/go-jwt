package common

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/speps/go-hashids"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const dbPath = "/tmp/DB"

var JwtSecret = []byte("pua-pua")

type Credentials struct {
	Email    string `json:"email, omitempty"`
	Password string `json:"Password"`
	ID       string `json:"id"`
}

type JwtToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func HandleRequests() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/signup", signUp)
	router.Handle("/signin", ValidateToken(http.HandlerFunc(signIn)))
	router.Handle("/getuserid/{email}", ValidateToken(http.HandlerFunc(getUserId)))
	router.Handle("/getaccesstoken", RefreshTokenMiddleware(http.HandlerFunc(getRefreshToken)))
	return router
}

func getUserId(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	email := vars["email"]
	e := r.Context().Value("email")
	if e != email {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	Id, err := getId(email)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(Id)
	return
}

func getId(email string) (Credentials, error) {
	var cred Credentials

	opts := badger.DefaultOptions(dbPath)
	opts.Dir = dbPath
	opts.ValueDir = dbPath
	db, err := badger.Open(opts)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(email))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			err := gob.NewDecoder(bytes.NewReader(val)).Decode(&cred)
			if err != nil {
				return err
			}
			return err
		})
		return err
	})
	return cred, err
}

func signIn(writer http.ResponseWriter, request *http.Request) {
	type response struct {
		Msg       string    `json:"msg"`
		TokenPair *JwtToken `json:"token-pair"`
	}

	var resp *response
	var creds *Credentials

	writer.Header().Set("Content-Type", "application/json")
	reqBody, _ := ioutil.ReadAll(request.Body)
	err := json.Unmarshal(reqBody, &creds)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := getUser(creds.Email)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	if user.Email == creds.Email && user.Password == creds.Password {
		tokenPair, err := createTokenPair(creds)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		val := fmt.Sprintf("Login successfull")
		resp = &response{Msg: val, TokenPair: tokenPair}

		json.NewEncoder(writer).Encode(resp)
	}
}

func signUp(writer http.ResponseWriter, request *http.Request) {
	type response struct {
		Msg       string    `json:"msg"`
		TokenPair *JwtToken `json:"token-pair"`
	}
	var cred *Credentials
	var result *response

	reqBody, _ := ioutil.ReadAll(request.Body)
	err := json.Unmarshal(reqBody, &cred)
	if err != nil {
		fmt.Fprintf(writer, "error parsing: %v", string(reqBody))
	}

	opts := badger.DefaultOptions(dbPath)
	opts.Dir = dbPath
	opts.ValueDir = dbPath
	db, err := badger.Open(opts)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()
	exists, _ := userExists(cred.Email, db)
	if !exists {
		id, err := generateUserId(cred)
		if err != nil {
			log.Fatal(err)
		}

		cred.ID = id
		err = createUser(cred, db)
		if err != nil {
			log.Fatal(err)
		}

		tokenPair, err := createTokenPair(cred)
		if err != nil {
			log.Println(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		val := fmt.Sprintf("User %s created successfully", cred.Email)
		result = &response{
			Msg:       val,
			TokenPair: tokenPair,
		}
		json.NewEncoder(writer).Encode(result)
	} else {
		val := fmt.Sprintf("User %s already exists", cred.Email)
		writer.Write([]byte(val))
	}
}

func getRefreshToken(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("credentials").(*Credentials)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	cred, err := getUser(user.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if user.Password == cred.Password && user.Email == cred.Email {
		log.Println("in true")
		newTokenPair, err := createTokenPair(cred)
		if err != nil {
			fmt.Fprintf(w, "Error creating new access token: %s", err)
			return
		}
		json.NewEncoder(w).Encode(newTokenPair)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func userExists(username string, db *badger.DB) (bool, error) {
	exists := true
	err := db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(username))
		if err != nil {
			exists = false
			return err
		}
		return err
	})

	return exists, err
}

func createUser(user *Credentials, db *badger.DB) error {
	err := db.Update(func(txn *badger.Txn) error {
		encUser := serialize(user)
		err := txn.Set([]byte(user.Email), encUser)
		if err != nil {
			log.Fatal(err)
		}
		return err
	})
	return err
}

func getUser(email string) (*Credentials, error) {
	var cred *Credentials
	opts := badger.DefaultOptions(dbPath)
	opts.Dir = dbPath
	opts.ValueDir = dbPath
	db, err := badger.Open(opts)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(email))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			err := gob.NewDecoder(bytes.NewReader(val)).Decode(&cred)

			if err != nil {
				log.Fatal(err)
			}
			return err
		})
		return err
	})
	return cred, err
}

func serialize(v interface{}) []byte {
	var res bytes.Buffer
	encoder := gob.NewEncoder(&res)
	err := encoder.Encode(v)
	if err != nil {
		log.Fatal(err)
	}

	return res.Bytes()
}

func generateUserId(cred *Credentials) (string, error) {
	data := bytes.Join([][]byte{[]byte(cred.Email), []byte(cred.Password)}, []byte{})
	hd := hashids.NewData()
	hd.Salt = string(data)
	h, err := hashids.NewWithData(hd)
	if err != nil {
		return "", err
	}

	id, _ := h.Encode([]int{1, 2, 3})
	return id, nil
}

func createTokenPair(cred *Credentials) (*JwtToken, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = cred.Email
	claims["sub"] = 1
	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	access_token, err := token.SignedString([]byte(JwtSecret))
	if err != nil {
		return nil, err
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["sub"] = 1
	rtClaims["exp"] = time.Now().Add(time.Hour * 10).Unix()
	refresh_token, err := refreshToken.SignedString([]byte(JwtSecret))
	if err != nil {
		return nil, err
	}

	return &JwtToken{AccessToken: access_token, RefreshToken: refresh_token}, nil
}
