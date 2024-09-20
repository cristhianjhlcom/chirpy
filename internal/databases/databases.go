package databases

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

var ErrorChirpNotFound = errors.New("chirp not found")
var ErrorUserNotFound = errors.New("user not found")
var ErrorUserTaken = errors.New("user already taken")
var ErrorUserNotExists = errors.New("user do not exists")

type DB struct {
	path string
	mux  *sync.RWMutex
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type RefreshToken struct {
	Token     string
	ExpiresAt time.Time
}

type User struct {
	Id           int    `json:"id"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	RefreshToken RefreshToken
	IsChirpyRed  bool `json:"is_chirpy_red"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	err := db.ensureDB()
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) CreateUser(email string, password string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, user := range dbStructure.Users {
		if user.Email == email {
			return User{}, ErrorUserTaken
		}
	}
	newID := len(dbStructure.Users) + 1
	newUser := User{
		Id:          newID,
		Email:       email,
		Password:    password,
		IsChirpyRed: false,
	}
	dbStructure.Users[newID] = newUser
	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}
	return newUser, nil
}

func (db *DB) SaveRefreshToken(id int, refreshToken string, expiresAt time.Time) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	user, exists := dbStructure.Users[id]
	if !exists {
		return fmt.Errorf("user not found")
	}
	refreshTokenEntry := RefreshToken{
		Token:     refreshToken,
		ExpiresAt: expiresAt,
	}
	user.RefreshToken = refreshTokenEntry
	dbStructure.Users[id] = user
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) UpdateUserMembreship(id int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	for _, user := range dbStructure.Users {
		if user.Id != id {
			return ErrorUserNotExists
		}
	}
	existingUser, ok := dbStructure.Users[id]
	if !ok {
		return fmt.Errorf("user with id %d not found", id)
	}
	existingUser.IsChirpyRed = true
	dbStructure.Users[id] = existingUser
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) UpdateUser(id int, email string, password string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, user := range dbStructure.Users {
		if user.Id != id {
			return User{}, ErrorUserNotExists
		}
	}
	existingUser, ok := dbStructure.Users[id]
	if !ok {
		return User{}, fmt.Errorf("user with id %d not found", id)
	}
	existingUser.Email = email
	existingUser.Password = password
	dbStructure.Users[id] = existingUser
	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}
	updatedUser := existingUser
	updatedUser.Password = ""
	return updatedUser, nil
}

func (db *DB) CreateChirp(body string, authorId int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	newID := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		Id:       newID,
		Body:     body,
		AuthorId: authorId,
	}
	dbStructure.Chirps[newID] = chirp
	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, err
	}
	return chirp, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}
	return chirps, nil
}

func (db *DB) SearchChirpsByAuthorId(id int) ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	chirps := make([]Chirp, 0, len(dbStructure.Chirps))
	for _, chirp := range dbStructure.Chirps {
		if chirp.AuthorId == id {
			chirps = append(chirps, chirp)
		}
	}
	return chirps, nil
}

func (db *DB) GetChirpById(id int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	chirp, exists := dbStructure.Chirps[id]
	if !exists {
		return Chirp{}, ErrorChirpNotFound
	}
	return chirp, nil
}

func (db *DB) DestroyChirpById(id int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	_, exists := dbStructure.Chirps[id]
	if !exists {
		return ErrorChirpNotFound
	}
	delete(dbStructure.Chirps, id)
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, user := range dbStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, ErrorUserNotFound
}

func (db *DB) GetUserIdByRefreshToken(token string) (int, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return 0, err
	}
	for _, user := range dbStructure.Users {
		if user.RefreshToken.Token == token {
			return user.Id, nil
		}
	}
	return 0, fmt.Errorf("refresh token not found")
}

func (db *DB) IsRefreshTokenExpired(token string) bool {
	dbStructure, err := db.loadDB()
	if err != nil {
		return true
	}
	for _, user := range dbStructure.Users {
		if user.RefreshToken.Token == token {
			return time.Now().After(user.RefreshToken.ExpiresAt)
		}
	}
	return true
}

func (db *DB) RevokeRefreshToken(token string) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}
	for id, user := range dbStructure.Users {
		if user.RefreshToken.Token == token {
			user.RefreshToken = RefreshToken{}
			dbStructure.Users[id] = user
			break
		}
	}
	err = db.writeDB(dbStructure)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); errors.Is(err, os.ErrNotExist) {
		return db.writeDB(DBStructure{
			Chirps: make(map[int]Chirp),
		})
	}
	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()
	data, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}
	var dbStructure DBStructure
	err = json.Unmarshal(data, &dbStructure)
	if err != nil {
		return DBStructure{}, err
	}
	return dbStructure, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()
	data, err := json.MarshalIndent(dbStructure, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0644)
}
