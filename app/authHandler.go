package app

import (
	"encoding/json"
	"net/http"

	"github.com/kal997/banking-auth/dto"
	"github.com/kal997/banking-auth/service"
	"github.com/kal997/banking-lib/errs"
	"github.com/kal997/banking-lib/logger"
)

type AuthHandler struct {
	service service.AuthService
}

func (ah AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {

	urlParams := make(map[string]string)

	// converting from query to map type
	for k, _ := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		appErr := ah.service.Verify(urlParams)

		if appErr != nil {
			writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {

		writeResponse(w, http.StatusForbidden, errs.NewAuthorizationError("Missing token"))

	}
}
func (ah AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, "Invalid request")
		return
	}

	token, appErr := ah.service.Login(loginRequest)
	if appErr != nil {
		writeResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeResponse(w, http.StatusOK, token)
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": true,
		"message":      msg}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		logger.Error("Encode failed with err " + err.Error())
		panic(err)
	}
}
