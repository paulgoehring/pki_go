/*
 * pki.in GO
 *
 * pki in API docs
 *
 * API version: 1.0.0
 * Contact: paul.goehring@student.uni-tuebingen.de
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = Logger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	return router
}

func NewRouter2() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes2 {
		var handler http.Handler
		handler = route.HandlerFunc

		//handler = Logger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}
	return router
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!")
}

var routes = Routes{
	Route{
		"Index",
		"GET",
		"/",
		Index,
	},

	Route{
		"GetChallengeGet",
		strings.ToUpper("Get"),
		"/getChallenge",
		GetChallengeGet,
	},

	Route{
		"GetTokenGet",
		strings.ToUpper("Get"),
		"/getToken",
		GetTokenGet,
	},

	Route{
		"GetTokenGet",
		strings.ToUpper("Get"),
		"/getCert",
		GetTokenGet,
	},
	Route{
		"GetNewTokenGet",
		strings.ToUpper("Get"),
		"/getNewCert",
		GetNewTokenGet,
	},
	Route{
		"GetNewChallengeGet",
		strings.ToUpper("Get"),
		"/getNewChallenge",
		GetNewChallengeGet,
	},
}

var routes2 = Routes{
	Route{
		"Index",
		"GET",
		"/",
		Index,
	},
	Route{
		"GetNewChallengeGet",
		strings.ToUpper("Get"),
		"/getNewChallenge",
		GetNewChallengeGet,
	},
	Route{
		"GetNewTokenGet",
		strings.ToUpper("Get"),
		"/getNewCert",
		GetNewTokenGet,
	},
}
