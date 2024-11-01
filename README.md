# frodo-lib
A Go library to manage PingOne Advanced Identity Cloud environments, ForgeOps deployments, and classic deployments.

It is a very basic clone of <https://github.com/rockcarver/frodo-lib> and currently supports `Authentication` use cases.

## Admin Login

```go
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/darkedges/go-frodo-lib"
	"net/http"
)

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	params := frodo.Params{}
	// Admin Login
	params.Host = ""
	params.User = ""
	params.Pass = ""
	myfrodo, _ := lib.CreateInstanceWithAdminAccount(params)
	myfrodo.Login()
	info := myfrodo.GetInfo()
	// Dump Details
	fmt.Printf("newFactoryHelperServiceAccountLogin: Logged in to: %s\n", info.Host)
	fmt.Printf("newFactoryHelperServiceAccountLogin: Logged in as: %s\n", info.AuthenticatedSubject)
	fmt.Printf("newFactoryHelperServiceAccountLogin: Using bearer token: \n%s\n", info.BearerToken)
	jcart, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(jcart))
}

```

## Service Account Login

```go
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/darkedges/go-frodo-lib"
	"net/http"
)

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	params := frodo.Params{}
	//// Service Account Login
	params.Host = ""
	params.ServiceAccountId = ""
	params.ServiceAccountJwk = ""
	myfrodo, _ := frodo.CreateInstanceWithServiceAccount(params)
	myfrodo.Login()
	info := myfrodo.GetInfo()
	// Dump Details
	fmt.Printf("newFactoryHelperServiceAccountLogin: Logged in to: %s\n", info.Host)
	fmt.Printf("newFactoryHelperServiceAccountLogin: Logged in as: %s\n", info.AuthenticatedSubject)
	fmt.Printf("newFactoryHelperServiceAccountLogin: Using bearer token: \n%s\n", info.BearerToken)
	jcart, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(jcart))
}

```