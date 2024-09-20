package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/cristhianjhlcom/chirpy/internal/databases"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// var chirps []Chirp
var mutex = &sync.Mutex{}

type apiConfig struct {
	fileserverHits int
	DB             *databases.DB
	jwtSecret      string
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId string `json:"author_id"`
}

type User struct {
	Id               int    `json:"id"`
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
	IsChirpyRed      bool   `json:"is_chirpy_red"`
}

type ChirpRequest struct {
	Body string `json:"body"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Valid       bool   `json:"valid"`
	CleanedBody string `json:"cleaned_body"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	hits := cfg.fileserverHits
	fmt.Fprintf(w, "Hits: %d", hits)
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	fmt.Fprintln(w, "Hits reset to 0")
}

func (cfg *apiConfig) handlerApiHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) handlerAdminMetrics(w http.ResponseWriter, r *http.Request) {
	hits := cfg.fileserverHits
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	const metricsTemplate = `
	<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited {{.Count}} times!</p>
	</body>
	</html>
	`
	data := struct {
		Count int
	}{
		Count: hits,
	}

	tmpl, err := template.New("metrics").Parse(metricsTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (cfg *apiConfig) handlerValidateChirp(w http.ResponseWriter, r *http.Request) {
	var chirp ChirpRequest
	err := json.NewDecoder(r.Body).Decode(&chirp)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}

	if len(chirp.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Chirp is too long"})
		return
	}

	badWords := [3]string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(chirp.Body, " ")
	for idx := 0; idx < len(words); idx++ {
		word := strings.ToLower(words[idx])
		for bad := 0; bad < len(badWords); bad++ {
			badWord := strings.ToLower(badWords[bad])
			if word == badWord {
				words[idx] = "****"
			}
		}
	}
	cleanedBody := strings.Join(words, " ")

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(SuccessResponse{
		Valid:       true,
		CleanedBody: cleanedBody,
	})
}

func (cfg *apiConfig) ChirpIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authorIdParam := r.URL.Query().Get("author_id")
	sortParam := r.URL.Query().Get("sort")
	if sortParam == "" {
		sortParam = "asc"
	}
	var chirps []databases.Chirp
	var err error
	if authorIdParam != "" {
		authorId, err := strconv.Atoi(authorIdParam)
		if err != nil {
			http.Error(w, "Search params not valid", http.StatusBadRequest)
			return
		}
		chirps, err = cfg.DB.SearchChirpsByAuthorId(authorId)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Could not retrive chirps"})
			return
		}
	} else {
		chirps, err = cfg.DB.GetChirps()
		if err != nil {
			http.Error(w, "Could not retrive chirps", http.StatusInternalServerError)
			return
		}
	}
	if sortParam == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].Id > chirps[j].Id
		})
	} else {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].Id < chirps[j].Id
		})
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(chirps)
}

func (cfg *apiConfig) ChirpShow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stringId := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	chirpId, err := strconv.Atoi(stringId)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	chirp, err := cfg.DB.GetChirpById(chirpId)
	if err != nil {
		if errors.Is(err, databases.ErrorChirpNotFound) {
			http.Error(w, "Chirp not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(chirp)
}

func (cfg *apiConfig) ChirpDestroy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stringId := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	chirpId, err := strconv.Atoi(stringId)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	jwtSecret := os.Getenv("JWT_SECRET")
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil },
	)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	if !token.Valid {
		http.Error(w, "Unauthorized: token is not valid", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		http.Error(w, "Unauthorized: token has expired", http.StatusUnauthorized)
		return
	}
	userId, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
		return
	}
	userIdNumber, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(w, "Invalid user Id", http.StatusBadRequest)
		return
	}
	chirp, err := cfg.DB.GetChirpById(chirpId)
	if chirp.AuthorId != userIdNumber {
		http.Error(w, "Unauthorized: this chirps do not below to you", http.StatusForbidden)
		return
	}
	err = cfg.DB.DestroyChirpById(chirpId)
	if err != nil {
		http.Error(w, "Something went wrong", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	json.NewEncoder(w).Encode(chirp)
}

func (cfg *apiConfig) ChirpStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newChirp Chirp

	err := json.NewDecoder(r.Body).Decode(&newChirp)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}

	if len(newChirp.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Chirp is too long"})
		return
	}

	badWords := [3]string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(newChirp.Body, " ")
	for idx := 0; idx < len(words); idx++ {
		word := strings.ToLower(words[idx])
		for bad := 0; bad < len(badWords); bad++ {
			badWord := strings.ToLower(badWords[bad])
			if word == badWord {
				words[idx] = "****"
			}
		}
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	jwtSecret := os.Getenv("JWT_SECRET")
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil },
	)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	if !token.Valid {
		http.Error(w, "Unauthorized: token is not valid", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		http.Error(w, "Unauthorized: token has expired", http.StatusUnauthorized)
		return
	}
	userId, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
		return
	}
	userIdNumber, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(w, "Invalid user Id", http.StatusBadRequest)
		return
	}
	cleanedBody := strings.Join(words, " ")
	createdChirp, err := cfg.DB.CreateChirp(cleanedBody, userIdNumber)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Could not save chirp"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdChirp)
}

func (cfg *apiConfig) UserStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newUser User

	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}
	createdUser, err := cfg.DB.CreateUser(newUser.Email, string(hashedPassword))
	if err != nil {
		if errors.Is(err, databases.ErrorUserTaken) {
			http.Error(w, "User already taken", http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Could not save user"})
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdUser)
}

func (cfg *apiConfig) UserUpdate(w http.ResponseWriter, r *http.Request) {
	type UpdateUserRequest struct {
		Id       int    `json:"id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	jwtSecret := os.Getenv("JWT_SECRET")
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil },
	)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	if !token.Valid {
		http.Error(w, "Unauthorized: token is not valid", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		http.Error(w, "Unauthorized: token has expired", http.StatusUnauthorized)
		return
	}
	userId, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
		return
	}
	userIdNumber, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(w, "Invalid user Id", http.StatusBadRequest)
		return
	}
	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}
	updatedUser, err := cfg.DB.UpdateUser(userIdNumber, req.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, "Something went wrong", http.StatusBadRequest)
		return
	}
	response := UpdateUserRequest{
		Id:    updatedUser.Id,
		Email: updatedUser.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) Login(w http.ResponseWriter, r *http.Request) {
	type LoginResponse struct {
		Id           int    `json:"id"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var user User
	expiresIn := 60 * 60 * 24
	if user.ExpiresInSeconds == 0 {
		user.ExpiresInSeconds = expiresIn
	} else if user.ExpiresInSeconds > expiresIn {
		user.ExpiresInSeconds = expiresIn
	}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}
	findedUser, err := cfg.DB.GetUserByEmail(user.Email)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Incorrect email or password"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(findedUser.Password), []byte(user.Password))
	fmt.Println("Contrase;a incorrecta -> ", err)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Incorrect email or password"})
		return
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(user.ExpiresInSeconds) * time.Second)),
		Subject:   fmt.Sprintf("%d", findedUser.Id),
	})
	token, err := tokenClaims.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}
	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		http.Error(w, "Could not generate refresh token", http.StatusInternalServerError)
		return
	}
	refreshToken := hex.EncodeToString(refreshTokenBytes)
	err = cfg.DB.SaveRefreshToken(findedUser.Id, refreshToken, time.Now().Add(60*24*time.Hour))
	if err != nil {
		http.Error(w, "Could not save refresh token", http.StatusInternalServerError)
		return
	}
	response := LoginResponse{
		Id:           findedUser.Id,
		Email:        findedUser.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  findedUser.IsChirpyRed,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")
	userId, err := cfg.DB.GetUserIdByRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if cfg.DB.IsRefreshTokenExpired(refreshToken) {
		http.Error(w, "Unauthorized: refresh token expired", http.StatusUnauthorized)
		return
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	expiresIn := time.Hour
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   fmt.Sprintf("%d", userId),
	})
	token, err := tokenClaims.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"token": token,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")
	err := cfg.DB.RevokeRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) PolkaWebhooks(w http.ResponseWriter, r *http.Request) {
	type PolkaRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserId int `json:"user_id"`
		}
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "ApiKey ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "ApiKey ")
	polkaSecret := os.Getenv("POLKA_KEY")
	if token != polkaSecret {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}
	var request PolkaRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}
	if request.Event != "user.upgraded" {
		http.Error(w, "Not allowed event", http.StatusNoContent)
		return
	}
	err = cfg.DB.UpdateUserMembreship(request.Data.UserId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	godotenv.Load()
	db, err := databases.NewDB("database.json")
	if err != nil {
		log.Fatal(err)
	}
	apiCfg := apiConfig{
		fileserverHits: 0,
		DB:             db,
	}
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServer))
	mux.HandleFunc("GET /api/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("/api/reset", apiCfg.handlerReset)
	mux.HandleFunc("GET /api/healthz", apiCfg.handlerApiHealth)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerAdminMetrics)
	// mux.HandleFunc("POST /api/validate_chirp", apiCfg.handlerValidateChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.ChirpIndex)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.ChirpShow)
	mux.HandleFunc("POST /api/chirps", apiCfg.ChirpStore)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.ChirpDestroy)
	mux.HandleFunc("POST /api/users", apiCfg.UserStore)
	mux.HandleFunc("PUT /api/users", apiCfg.UserUpdate)
	mux.HandleFunc("POST /api/login", apiCfg.Login)
	mux.HandleFunc("POST /api/refresh", apiCfg.Refresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.Revoke)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.PolkaWebhooks)
	log.Fatal(server.ListenAndServe())
}
