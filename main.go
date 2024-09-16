package main

import (
    "net/http"
    "fmt"
)

type apiConfig struct {
    fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
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

func main() {
    apiCfg := &apiConfig{}
    mux := http.NewServeMux()

    server := &http.Server{
        Addr: ":8080",
        Handler: mux,
    }

    fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

    mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServer))

    mux.HandleFunc("GET /metrics", apiCfg.handlerMetrics)

    mux.HandleFunc("/reset", apiCfg.handlerReset)

    mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, req *http.Request) {
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })

    err := server.ListenAndServe()

    if err != nil {
        panic(err)
    }
}
