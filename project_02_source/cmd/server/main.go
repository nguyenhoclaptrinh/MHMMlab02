package main

import (
	"log"
	"net/http"

	"lab02/pkg/server/handlers"
	"lab02/pkg/server/storage"
)

const (
	Port   = ":8080"
	DBFile = "server.db"
)

func main() {
	// Khởi tạo Database
	db, err := storage.InitDB(DBFile)
	if err != nil {
		log.Fatal("Lỗi khởi tạo database:", err)
	}
	defer db.Close()

	// Khởi tạo Logic Handlers
	srv := handlers.NewServer(db)

	// Routing
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// Start Server
	log.Printf("Máy chủ đang khởi động tại %s...", Port)
	log.Fatal(http.ListenAndServe(Port, mux))
}
