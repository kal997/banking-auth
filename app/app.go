package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/kal997/banking-auth/domain"
	"github.com/kal997/banking-auth/service"
	"github.com/kal997/banking-lib/logger"
)

func Start() {

	sanityCheck()

	router := mux.NewRouter()

	dbClient := getDbClient()

	authRepository := domain.NewAuthRepository(dbClient)
	authService := service.NewLoginService(authRepository, domain.GetRolePermissions())

	authh := AuthHandler{service: authService}

	router.
		HandleFunc("/auth/login", authh.Login).
		Methods(http.MethodPost)

	router.
		HandleFunc("/auth/verify", authh.Verify).
		Methods(http.MethodGet)

	// starting server
	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	logger.Info(fmt.Sprintf("Starting Auth server on %s %s ...", address, port))
	logger.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router).Error())

}

func sanityCheck() {
	if os.Getenv("SERVER_ADDRESS") == "" {
		log.Fatal("SERVER_ADDRESS is missing..")

	}

	if os.Getenv("SERVER_PORT") == "" {
		log.Fatal("SERVER_PORT is missing..")
	}

	if os.Getenv("DB_USER") == "" {
		log.Fatal("DB_USER is missing..")
	}

	if os.Getenv("DB_PASSWD") == "" {
		log.Fatal("DB_PASSWD is missing..")
	}
	if os.Getenv("DB_ADDR") == "" {
		log.Fatal("DB_ADDR is missing..")
	}
	if os.Getenv("DB_PORT") == "" {
		log.Fatal("DB_PORT is missing..")
	}
	if os.Getenv("DB_NAME") == "" {
		log.Fatal("DB_NAME is missing..")
	}

}

func getDbClient() *sqlx.DB {
	dbUser := os.Getenv("DB_USER")
	dbPasWD := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDR")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dataSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPasWD, dbAddr, dbPort, dbName)
	client, err := sqlx.Open("mysql", dataSource)
	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	return client

}
