package frodo

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/darkedges/go-frodo-lib/constants"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/exp/slices"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var autoRefresh = false
var forceLoginAsUser = false
var fidcClientId = "idmAdminClient"
var forgeopsClientId = "idm-admin-ui"
var adminClientId = fidcClientId
var adminClientPassword = "doesnotmatter"

type Params struct {
	Host, User, Pass        string
	Realm                   string
	DeploymentType          string
	AllowInsecureConnection bool
	Debug                   bool
	Curlirize               bool
	ServiceAccountId        string
	ServiceAccountJwk       string
	OTPSecret               string
}

type ImFrodo interface {
	Login()
	GetInfo() PlatformInfo
	state() State
	GetServiceAccount(ServiceAccountParams) ServiceAccountType
}

type PlatformInfo struct {
	AmVersion            string
	Host                 string
	AuthenticatedSubject string
	DeploymentType       string
	CookieName           string
	SessionToken         string
	BearerToken          string
	CloudInfo            EnvInfoInterface
}

type Frodo struct {
	State *State
}

func (frodo Frodo) state() State {
	//TODO implement me
	panic("implement me")
}

func (frodo Frodo) Login() {
	frodo.GetTokens()
	frodo.DebugMessage("Frodo: login")
	frodo.VerboseMessage("Frodo: login")
}

func (frodo Frodo) GetInfo() PlatformInfo {
	state := frodo.State
	info := PlatformInfo{
		Host:                 state.getHost(),
		AmVersion:            frodo.getAmVersion(),
		AuthenticatedSubject: frodo.getAuthenticatedSubject(),
		DeploymentType:       state.getDeploymentType(),
		CookieName:           state.CookieName,
		SessionToken:         state.getCookieValue(),
	}
	if state.getBearerToken() != (AccessTokenMetaType{}) {
		info.BearerToken = state.getBearerToken().AccessToken
	}
	if state.getDeploymentType() == constants.CloudDeploymentTypeKey {
		info.CloudInfo = frodo.getCloudInfo()
	}
	return info
}

func CreateInstanceWithAdminAccount(p Params) (ImFrodo, error) {
	instance := Frodo{
		State: &State{
			host:     p.Host,
			username: p.User,
			password: p.Pass,
			realm:    p.Realm,
		},
	}
	return instance, nil
}

func CreateInstanceWithAdminAccountTOTP(p Params) (ImFrodo, error) {
	instance := Frodo{
		State: &State{
			host:      p.Host,
			username:  p.User,
			password:  p.Pass,
			realm:     p.Realm,
			OTPSecret: p.OTPSecret,
		},
	}
	return instance, nil
}

func CreateInstanceWithServiceAccount(p Params) (ImFrodo, error) {
	instance := Frodo{
		State: &State{
			host:              p.Host,
			serviceAccountId:  p.ServiceAccountId,
			serviceAccountJwk: p.ServiceAccountJwk,
			realm:             p.Realm,
		},
	}
	return instance, nil
}

func (state State) DebugHandler() func(string) {
	return func(message string) {
		//fmt.Println(message)
	}
}

func (state State) VerboseHandler() func(string) {
	return func(message string) {
		//fmt.Println(message)
	}
}

func (frodo Frodo) DebugMessage(message string) {
	handler := frodo.State.DebugHandler()
	if handler != nil {
		handler(message)
	}
}

func (frodo Frodo) VerboseMessage(message string) {
	handler := frodo.State.VerboseHandler()
	if handler != nil {
		handler(message)
	}
}

type GetTokenParams struct {
	forceLoginAsUser bool
	autorefresh      bool
	types            string
	callbackHandler  string
	State            State
}

type SaveConnectionProfileParams struct {
	host string
}

type Tokens struct {
	bearerToken      AccessTokenMetaType
	userSessionToken UserSessionMetaType
	subject          any
	host             string
	realm            any
}

func (frodo Frodo) GetTokens() Tokens {
	state := frodo.State
	usingConnectionProfile := false
	// todo
	if state.getUsername() == "" && state.getPassword() == "" && state.getServiceAccountId() != "" && state.getServiceAccountJwk() != "" {
		usingConnectionProfile = frodo.loadConnectionProfile()
		if state.getDeploymentType() != "" && !slices.Contains(constants.DeploymentTypes, state.getDeploymentType()) {
			errorString := fmt.Sprintf("Unsupported deployment type: %s", state.getDeploymentType())
			panic(errorString)
		}
	}
	if !isValidUrl(state.getHost()) {
		conn, _ := frodo.getConnectionProfile()
		state.setHost(conn.tenant)
		state.AllowInsecureConnection = conn.allowInsecureConnection
		state.setDeploymentType(conn.deploymentType)

		// fail fast if deployment type not applicable
		if state.getDeploymentType() != "" && !slices.Contains(constants.DeploymentTypes, state.getDeploymentType()) {
			errorString := fmt.Sprintf("Unsupported deployment type: %s", state.getDeploymentType())
			panic(errorString)
		}
	}
	state.CookieName = frodo.determineCookieName()
	// use service account to login?
	if !forceLoginAsUser && (state.getDeploymentType() == constants.CloudDeploymentTypeKey || state.getDeploymentType() == "") && state.getServiceAccountId() != "" && state.getServiceAccountJwk() != "" {
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getTokens: Authenticating with service account %s", state.getServiceAccountId()))
		//try {
		token, err := frodo.getSaBearerToken()
		if err != nil {
		}
		if token != (AccessTokenMetaType{}) {
			state.setBearerToken(token)
		}

		if usingConnectionProfile && !token.from_cache {
			frodo.saveConnectionProfile(SaveConnectionProfileParams{host: state.getHost()})
		}
		state.setUseBearerTokenForAmApis(true)
		frodo.determineDeploymentTypeAndDefaultRealmAndVersion()
		if state.getDeploymentType() != "" && !slices.Contains(constants.DeploymentTypes, state.getDeploymentType()) {
			panic(fmt.Sprintf("Unsupported deployment type '%s'", state.getDeploymentType()))
		}
	} else if state.getUsername() != "" && state.getPassword() != "" {
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getTokens: Authenticating with user account %s", state.getUsername()))
		token := frodo.getUserSessionToken(frodo.CallbackHandler())
		if token.tokenId != "" {
			state.userSessionToken = token
		}

		if usingConnectionProfile && !token.from_cache {
			frodo.saveConnectionProfile(SaveConnectionProfileParams{host: state.getHost()})
		}
		frodo.determineDeploymentTypeAndDefaultRealmAndVersion()
		//
		//// fail if deployment type not applicable
		if state.getDeploymentType() != "" && !slices.Contains(constants.DeploymentTypes, state.getDeploymentType()) {
			panic(fmt.Sprintf("Unsupported deployment type '%s'", state.getDeploymentType()))
		}
		if state.getCookieValue() != "" && (state.getDeploymentType() == constants.CloudDeploymentTypeKey || state.getDeploymentType() == constants.ForgeopsDeploymentTypeKey) {
			accessToken := frodo.getUserBearerToken()
			if accessToken != (AccessTokenMetaType{}) {
				state.setBearerToken(accessToken)
			}
		}
	} else {
		panic("Incomplete or no credentials")
	}
	if state.getCookieValue() != "" || (state.getUseBearerTokenForAmApis() && state.getBearerToken().AccessToken != "") {
		if state.getBearerToken().from_cache {
			frodo.VerboseMessage("Using cached bearer token.")
		}
		if state.getUseBearerTokenForAmApis() && state.userSessionToken.from_cache {
			frodo.VerboseMessage("Using cached session token.")
		}
	}
	frodo.scheduleAutoRefresh(forceLoginAsUser, autoRefresh)
	tokens := Tokens{
		bearerToken:      state.getBearerToken(),
		userSessionToken: state.userSessionToken,
		subject:          frodo.getLoggedInSubject(),
		host:             state.getHost(),
	}
	if state.getRealm() != "" {
		tokens.realm = state.getRealm()
	} else {
		tokens.realm = "root"
	}
	frodo.DebugMessage("AuthenticateOps.getTokens: end with tokens")
	return tokens
}

func isValidUrl(host string) bool {
	_, err := url.ParseQuery(host)
	if err != nil {
		return false
	}
	return true
}

func (frodo *Frodo) loadConnectionProfile() bool {
	return frodo.loadConnectionProfileByHost(frodo.State.getHost())
}

func (frodo *Frodo) loadConnectionProfileByHost(host string) bool {
	conn, err := frodo.getConnectionProfileByHost(host)
	if err != nil {
		return false
	}
	state := frodo.State
	state.setHost(conn.tenant)
	if state.IdmHost == "" {
		state.IdmHost = conn.idmHost
	}
	state.AllowInsecureConnection = conn.allowInsecureConnection
	if state.getDeploymentType() == "" {
		state.setDeploymentType(conn.deploymentType)
	}
	if state.AdminClientId == "" {
		state.AdminClientId = conn.adminClientId
	}
	if state.AdminClientRedirectUri == "" {
		state.AdminClientRedirectUri = conn.adminClientRedirectUri
	}
	state.setUsername(conn.username)
	state.setPassword(conn.password)
	state.setAuthenticationService(conn.authenticationService)
	state.AuthenticationHeaderOverrides = conn.authenticationHeaderOverrides
	state.setServiceAccountId(conn.svcacctId)
	state.setServiceAccountJwk(conn.svcacctJwk)
	state.ServiceAccountScope = conn.svcacctScope
	return true
}

type ConnectionProfileInterface struct {
	tenant                        string
	idmHost                       string
	deploymentType                string
	authenticationHeaderOverrides string
	svcacctId                     string
	svcacctJwk                    string
	svcacctScope                  string
	authenticationService         string
	password                      string
	username                      string
	adminClientRedirectUri        string
	adminClientId                 string
	allowInsecureConnection       string
}

func (frodo *Frodo) getConnectionProfileByHost(host string) (ConnectionProfileInterface, error) {
	if host == "" {
		return ConnectionProfileInterface{}, fmt.Errorf("host cannot be empty")
	}
	return ConnectionProfileInterface{
		tenant:                        "1",
		idmHost:                       "2",
		deploymentType:                "classic",
		authenticationHeaderOverrides: "3",
		svcacctId:                     "4",
		svcacctJwk:                    "5",
		svcacctScope:                  "6",
		authenticationService:         "7",
		password:                      "8",
		username:                      "9",
		adminClientRedirectUri:        "10",
		adminClientId:                 "11",
		allowInsecureConnection:       "12",
	}, nil
}

func (frodo Frodo) getConnectionProfile() (ConnectionProfileInterface, error) {
	return frodo.getConnectionProfileByHost(frodo.State.getHost())
}

func (frodo Frodo) determineCookieName() string {
	data, err := frodo.getServerInfo()
	if err != nil {
		panic(err)
	}
	frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineCookieName: cookieName=%s", data["cookieName"].(string)))
	return data["cookieName"].(string)
}

type HTTPRequestParams struct {
	resource        map[string]string
	requestOverride map[string]string
	url             string
	method          string
	body            string
	headers         http.Header
	authenticate    bool
}

func (frodo Frodo) getServerInfo() (map[string]interface{}, error) {
	urlString := fmt.Sprintf(constants.ServerInfoUrlTemplate, frodo.State.getHost(), "*")
	data := frodo.generateAmApi(HTTPRequestParams{
		resource: map[string]string{
			"apiVersion": constants.ServerInfoApiVersion,
		},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "GET",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := client.Do(&data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body) // response body is []byte
	var responseObject map[string]interface{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

const userAgent = "frodo/0.0.1"

func (frodo Frodo) generateIdmApi(params HTTPRequestParams) http.Request {
	state := frodo.State
	u, err := url.Parse(params.url)
	if err != nil {
		panic(err)
	}
	req := http.Request{
		Method: params.method,
		URL:    u,
	}
	if params.body != "" {
		jsonBody := []byte(params.body)
		bodyReader := bytes.NewReader(jsonBody)
		req.Body = io.NopCloser(bodyReader)
	}
	req.Header = http.Header{
		"User-Agent":                {userAgent},
		"X-ForgeRock-TransactionId": {fmt.Sprintf("frodo-%s", uuid.New().String())},
		"Content-Type":              {"application/json"},
	}
	if state.getUseBearerTokenForAmApis() && state.getBearerToken().AccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.getBearerToken().AccessToken))
	}
	return req
}

func (frodo Frodo) generateAmApi(params HTTPRequestParams) http.Request {
	state := frodo.State
	u, err := url.Parse(params.url)
	if err != nil {
		panic(err)
	}
	req := http.Request{
		Method: params.method,
		URL:    u,
	}
	if params.body != "" {
		jsonBody := []byte(params.body)
		bodyReader := bytes.NewReader(jsonBody)
		req.Body = io.NopCloser(bodyReader)
	}
	req.Header = http.Header{
		"User-Agent":                {userAgent},
		"X-ForgeRock-TransactionId": {fmt.Sprintf("frodo-%s", uuid.New().String())},
		"Content-Type":              {"application/json"},
	}
	if params.resource["apiVersion"] != "" {
		req.Header.Set("Accept-API-Version", params.resource["apiVersion"])
	}
	if !state.getUseBearerTokenForAmApis() && state.CookieName != "" && state.getCookieValue() != "" {
		req.Header.Set(state.CookieName, state.getCookieValue())
	}
	if state.getUseBearerTokenForAmApis() && state.getBearerToken().AccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.getBearerToken().AccessToken))
	}
	for headerName, headerValue := range params.headers {
		req.Header.Set(headerName, strings.Join(headerValue, ", "))
	}
	return req
}

type FreshUserSessionTokenParams struct {
	otpCallbackHandler interface{}
}

func (frodo Frodo) getUserSessionToken(handler func(map[string]interface{})) UserSessionMetaType {
	frodo.DebugMessage("AuthenticateOps.getUserSessionToken: start")
	state := frodo.State
	token := UserSessionMetaType{}
	if state.UseTokenCache && state.HasUserSessionToken() {
		token := frodo.ReadUserSessionToken()
		token.from_cache = true
		frodo.DebugMessage("AuthenticateOps.getUserSessionToken: cached")
	}
	if token == (UserSessionMetaType{}) {
		token = frodo.getFreshUserSessionToken(FreshUserSessionTokenParams{
			otpCallbackHandler: frodo.OTPCallbackHandler,
		})
		token.from_cache = false
		frodo.DebugMessage("AuthenticateOps.getUserSessionToken: fresh")
	}

	if state.UseTokenCache {
		frodo.saveUserSessionToken(token)
	}
	frodo.DebugMessage("AuthenticateOps.getUserSessionToken: end")
	return token
}

func (frodo Frodo) CallbackHandler() func(map[string]interface{}) {
	return func(map[string]interface{}) {
		//fmt.Println("CallbackHandler")
	}
}

type CallbackHandlerResponse struct {
	NextStep  bool
	Need2FA   bool
	Factor    string
	Supported bool
	Payload   map[string]interface{}
}

func (frodo Frodo) OTPCallbackHandler() func(map[string]interface{}) map[string]interface{} {
	return func(callback map[string]interface{}) map[string]interface{} {
		passcode, err := totp.GenerateCodeCustom(frodo.State.OTPSecret, time.Now(), totp.ValidateOpts{
			Period: 30,
			Skew:   1,
			Digits: otp.DigitsSix,
		})
		if err != nil {
			panic(err)
		}
		o := callback["callbacks"].([]interface{})[0]
		p := o.(map[string]interface{})["input"].([]interface{})[0]
		p.(map[string]interface{})["value"] = passcode
		return callback
	}
}

type UserSessionMetaType struct {
	from_cache bool
	tokenId    string
	successUrl string
	realm      string
	expires    time.Time
}

type ReadTokenParam struct {
	tokenType string
}

func (frodo Frodo) ReadUserSessionToken() UserSessionMetaType {
	return frodo.ReadToken(ReadTokenParam{
		tokenType: "userSession",
	})
}
func (frodo Frodo) ReadToken(params ReadTokenParam) UserSessionMetaType {
	frodo.DebugMessage("TokenCacheOps.readToken: start")
	frodo.DebugMessage("TokenCacheOps.readToken: end")
	return UserSessionMetaType{}
}

type StepConfig struct {
	headers http.Header
	body    string
	service string
	realm   string
}

type SessionInfoParams struct {
	tokenId string
}

type CheckAndHandle2FAParams struct {
	payload            map[string]interface{}
	OTPCallbackHandler func(map[string]interface{}) map[string]interface{}
}

func (frodo Frodo) getFreshUserSessionToken(params FreshUserSessionTokenParams) UserSessionMetaType {
	frodo.DebugMessage("AuthenticateOps.getFreshUserSessionToken: start")
	state := frodo.State
	response, err := frodo.Step(
		StepConfig{
			body: "{}",
			headers: http.Header{
				"X-OpenAM-Username": {state.getUsername()},
				"X-OpenAM-Password": {state.getPassword()},
			},
		})
	if err != nil {
		panic(err)
	}
	//
	skip2FA := CallbackHandlerResponse{
		NextStep: true,
	}
	var steps = 0
	maxSteps := 3
	for ok := true; ok; ok = skip2FA.NextStep && steps < maxSteps {
		skip2FA = frodo.checkAndHandle2FA(
			CheckAndHandle2FAParams{
				payload:            response,
				OTPCallbackHandler: frodo.OTPCallbackHandler(),
			},
		)
		// throw exception if 2fa required but Factor not Supported by frodo (e.g. WebAuthN)
		if !skip2FA.Supported {
			panic(fmt.Sprintf("Unsupported 2FA Factor: %s", skip2FA.Factor))
		}

		if skip2FA.NextStep {
			steps++
			jsonBody, err := json.Marshal(skip2FA.Payload)
			if err != nil {
				panic(err.Error())
			}
			response, err = frodo.Step(
				StepConfig{
					body: string(jsonBody),
				},
			)
		}
		sessionInfo := SessionInfoType{}
		if response["tokenId"] != nil {
			response["from_cache"] = false
			// get session expiration
			sessionInfo = frodo.getSessionInfo(
				SessionInfoParams{
					tokenId: response["tokenId"].(string),
				},
			)
			response["expires"] = sessionInfo.MaxIdleExpirationTime
			frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getFreshUserSessionToken: end [tokenId=%s]", response["tokenId"]))
			frodo.DebugMessage(fmt.Sprintf("%s", response))
			return UserSessionMetaType{
				tokenId:    response["tokenId"].(string),
				successUrl: response["successUrl"].(string),
				realm:      response["realm"].(string),
				expires:    response["expires"].(time.Time),
				from_cache: response["from_cache"].(bool),
			}
		}
	}
	frodo.DebugMessage("AuthenticateOps.getFreshUserSessionToken: end [no session]")
	return UserSessionMetaType{}
}

func (frodo Frodo) saveUserSessionToken(token UserSessionMetaType) {
	frodo.DebugMessage("TokenCacheOps.saveUserSessionToken: start")
	frodo.DebugMessage("TokenCacheOps.saveUserSessionToken: end")
}

func (frodo Frodo) Step(config StepConfig) (map[string]interface{}, error) {
	state := frodo.State
	var urlString string
	if config.service != "" || state.getAuthenticationService() != "" {
		urlString = fmt.Sprintf(constants.AuthenticateWithServiceUrlTemplate, state.getHost(), getRealmPath(config.realm), config.service)
	} else {
		urlString = fmt.Sprintf(constants.AuthenticateUrlTemplate, state.getHost(), getRealmPath(config.realm))
	}
	var data = frodo.generateAmApi(HTTPRequestParams{
		resource: map[string]string{
			"apiVersion": constants.ApiVersion,
		},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "POST",
		body:            config.body,
		headers:         config.headers,
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	responseData, err := ioutil.ReadAll(resp.Body) // response body is []byte
	var responseObject map[string]interface{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

type SessionInfoType struct {
	LatestAccessTime         time.Time `json:"latestAccessTime"`
	MaxIdleExpirationTime    time.Time `json:"maxIdleExpirationTime"`
	MaxSessionExpirationTime time.Time `json:"maxSessionExpirationTime"`
	Properties               struct {
		AMCtxID string `json:"AMCtxId"`
	} `json:"properties"`
	Realm       string `json:"realm"`
	UniversalID string `json:"universalId"`
	Username    string `json:"username"`
}

func (frodo Frodo) getSessionInfo(i SessionInfoParams) SessionInfoType {
	state := frodo.State
	urlString := fmt.Sprintf(constants.SessionInfoURLTemplate, state.getHost(), frodo.getCurrentRealmPath())
	var data = frodo.generateAmApi(HTTPRequestParams{
		resource: map[string]string{
			"apiVersion": "resource=4.0",
		},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "POST",
		body:            "{\"tokenId\": \"" + i.tokenId + "\"}",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body) // response body is []byte
	var responseObject SessionInfoType
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject
}

func (frodo Frodo) getCurrentRealmPath() string {
	return getRealmPath(frodo.State.getRealm())
}

func (frodo Frodo) saveConnectionProfile(params SaveConnectionProfileParams) {
	panic("implement me")
}

func (frodo Frodo) determineDeploymentTypeAndDefaultRealmAndVersion() {
	state := frodo.State
	frodo.DebugMessage("AuthenticateOps.determineDeploymentTypeAndDefaultRealmAndVersion: start")
	state.setDeploymentType(frodo.determineDeploymentType())
	frodo.determineDefaultRealm()
	frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentTypeAndDefaultRealmAndVersion: realm=%s, type=%s", state.getRealm(), state.getDeploymentType()))
	versionInfo := frodo.getServerVersionInfo()
	frodo.DebugMessage(fmt.Sprintf("Full version: %+v", versionInfo.FullVersion))
	version, _ := frodo.getSemanticVersion(versionInfo)
	state.AmVersion = version
	frodo.DebugMessage("AuthenticateOps.determineDeploymentTypeAndDefaultRealmAndVersion: end")
}
func encodeBase64Url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func randomBytes(n int) ([]byte, error) {
	randomBytes := make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func (frodo Frodo) determineDeploymentType() string {
	frodo.DebugMessage("AuthenticateOps.determineDeploymentType: start")
	state := frodo.State
	cookieValue := state.getCookieValue()
	deploymentType := state.getDeploymentType()
	switch deploymentType {

	case constants.CloudDeploymentTypeKey:
		adminClientId = state.AdminClientId
		if adminClientId == "" {
			adminClientId = fidcClientId
		}
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
		return deploymentType
	case constants.ForgeopsDeploymentTypeKey:
		adminClientId = state.AdminClientId
		if adminClientId == "" {
			adminClientId = forgeopsClientId
		}
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
		return deploymentType
	case constants.ClassicDeploymentTypeKey:
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
		return deploymentType
	default:
		// if we are using a service account, we know it's cloud
		if state.getUseBearerTokenForAmApis() {
			frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", constants.CloudDeploymentTypeKey))
			return constants.CloudDeploymentTypeKey
		}
		verifier, _ := randomBytes(32)
		encodedVerifier := encodeBase64Url(verifier)
		hash := sha256.New()
		hash.Write([]byte(encodedVerifier))
		challenge := encodeBase64Url(hash.Sum(nil))
		challengeMethod := "S256"
		redirectUri, _ := url.Parse(state.getHost())
		redirectUri.Path = constants.RedirectUrlTemplate
		bodyFormData := fmt.Sprintf("redirect_uri=%s&scope=%s&response_type=code&client_id=%s&csrf=%s&decision=allow&code_challenge=%s&code_challenge_method=%s", url.QueryEscape(redirectUri.String()), url.QueryEscape(constants.CloudAdminScopes), url.QueryEscape(fidcClientId), url.QueryEscape(cookieValue), url.QueryEscape(challenge), url.QueryEscape(challengeMethod))
		deploymentType = constants.ClassicDeploymentTypeKey
		var data = frodo.authorize(HTTPRequestParams{
			url:  state.getHost(),
			body: bodyFormData,
			headers: http.Header{
				state.CookieName: {state.getCookieValue()},
				"Content-Type":   {"application/x-www-form-urlencoded"},
			},
			method: http.MethodPost,
		})
		client := &http.Client{
			Timeout: time.Second * 10,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, _ := client.Do(&data)
		if resp.StatusCode == 302 && strings.Index(resp.Header.Get("Location"), "code=") > -1 {
			frodo.VerboseMessage("ForgeRock Identity Cloud deployment detected.")
			deploymentType = constants.CloudDeploymentTypeKey
		} else {
			bodyFormData = fmt.Sprintf("redirect_uri=%s&scope=%s&response_type=code&client_id=%s&csrf=%s&decision=allow&code_challenge=%s&code_challenge_method=%s", url.QueryEscape(redirectUri.String()), url.QueryEscape(constants.ForgeopsAdminScopes), url.QueryEscape(forgeopsClientId), url.QueryEscape(cookieValue), url.QueryEscape(challenge), url.QueryEscape(challengeMethod))
			var data = frodo.authorize(HTTPRequestParams{
				url:  state.getHost(),
				body: bodyFormData,
				headers: http.Header{
					state.CookieName: {state.getCookieValue()},
					"Content-Type":   {"application/x-www-form-urlencoded"},
				},
				method: http.MethodPost,
			})
			resp, _ := client.Do(&data)
			if resp.StatusCode == 302 && strings.Index(resp.Header.Get("Location"), "code=") > -1 {
				adminClientId = state.AdminClientId
				if adminClientId == "" {
					adminClientId = forgeopsClientId
				}
				frodo.VerboseMessage("ForgeOps deployment detected.")
				deploymentType = constants.ForgeopsDeploymentTypeKey
			} else {
				frodo.DebugMessage("Classic deployment detected.")
			}
		}
	}
	frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
	return deploymentType
}

type VersionInfoType struct {
	fullVersion string
}

type ServerVersionInfoType struct {
	ID          string `json:"_id"`
	Rev         string `json:"_rev"`
	Version     string `json:"version"`
	FullVersion string `json:"fullVersion"`
	Revision    string `json:"revision"`
	Date        string `json:"date"`
}

func (frodo Frodo) getServerVersionInfo() ServerVersionInfoType {
	state := frodo.State
	urlString := fmt.Sprintf(constants.ServerInfoUrlTemplate, state.getHost(), "version")
	var data = frodo.generateAmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "GET",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body) // response body is []byte
	var responseObject ServerVersionInfoType
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject
}

type SemanticVersion struct {
}

func (frodo Frodo) getSemanticVersion(versionInfo ServerVersionInfoType) (string, error) {
	version := versionInfo.Version
	rx := regexp.MustCompile(`([\d]\.[\d]\.[\d](\.[\d])*)`)
	versionMatch := rx.FindStringSubmatch(version)
	if len(versionMatch) > 0 {
		return versionMatch[0], nil
	}
	return "", errors.New("Cannot extract semantic version from version info object.")
}

func (frodo Frodo) determineDefaultRealm() {
	state := frodo.State
	if state.getRealm() != "" {
		state.setRealm(constants.DeploymentTypeRealmMap[state.getDeploymentType()])
	}
}

func (frodo Frodo) scheduleAutoRefresh(user bool, refresh any) {

}

func (frodo Frodo) getLoggedInSubject() string {
	return ""
}

func (frodo Frodo) getAmVersion() string {
	versionObj := frodo.getServerVersionInfo()
	amVersion := fmt.Sprintf("%s Build %s (%s)", versionObj.Version, versionObj.Revision, versionObj.Date)
	return amVersion
}

type ServiceAccountParams struct {
	ServiceAccountId string
}

func (frodo Frodo) getAuthenticatedSubject() string {
	state := frodo.State
	var subjectString = fmt.Sprintf("%s (User)", state.getUsername())
	if state.getUseBearerTokenForAmApis() {
		serviceAccount := frodo.GetServiceAccount(ServiceAccountParams{
			ServiceAccountId: state.getServiceAccountId(),
		})
		subjectString = fmt.Sprintf("%s[%s] (Service Account)", serviceAccount.Name, state.getServiceAccountId())
	}
	return subjectString
}

type ServiceAccountType struct {
	ID             string   `json:"_id"`
	Rev            string   `json:"_rev"`
	AccountStatus  string   `json:"accountStatus"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Scopes         []string `json:"scopes"`
	Jwks           string   `json:"jwks"`
	MaxCachingTime string   `json:"maxCachingTime"`
	MaxIdleTime    string   `json:"maxIdleTime"`
	MaxSessionTime string   `json:"maxSessionTime"`
	QuotaLimit     string   `json:"quotaLimit"`
}

type ManagedObjectParams struct {
	Type   string
	Id     string
	Fields []string
}

func (frodo Frodo) GetServiceAccount(params ServiceAccountParams) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.GetServiceAccount: start")
	serviceAccount := frodo.getManagedObject(ManagedObjectParams{
		Type:   constants.MOType,
		Id:     params.ServiceAccountId,
		Fields: []string{"*"},
	})
	frodo.DebugMessage(fmt.Sprintf("%+v", serviceAccount))
	frodo.DebugMessage("ServiceAccountOps.GetServiceAccount: end")
	return serviceAccount
}

func getRealmPath(realm string) string {
	if realm == "" {
		realm = "/root"
	}
	if strings.HasPrefix(realm, "/") {
		realm = realm[1:]
	}
	elements := []string{}
	for _, element := range strings.Split(realm, "/") {
		if element != "" {
			elements = append(elements, element)
		}
	}
	realmPath := fmt.Sprintf("/realms/%s", strings.Join(elements, "/realms/"))
	return realmPath
}

func (frodo Frodo) authorize(params HTTPRequestParams) http.Request {
	urlString := fmt.Sprintf(constants.AuthorizeUrlTemplate, params.url, "")
	params.url = urlString
	return frodo.generateOauth2Api(params)
}

func (frodo Frodo) accessToken(params HTTPRequestParams) http.Request {
	urlString := fmt.Sprintf(constants.AccessTokenUrlTemplate, params.url, frodo.getCurrentRealmPath())
	params.url = urlString
	return frodo.generateOauth2Api(params)
}

func (frodo Frodo) generateOauth2Api(params HTTPRequestParams) http.Request {
	state := frodo.State
	u, err := url.Parse(params.url)
	if err != nil {
		panic(err)
	}
	req := http.Request{
		Method: params.method,
		URL:    u,
	}
	if params.body != "" {
		jsonBody := []byte(params.body)
		bodyReader := bytes.NewReader(jsonBody)
		req.Body = io.NopCloser(bodyReader)
	}
	req.Header = http.Header{
		"User-Agent":                {userAgent},
		"X-ForgeRock-TransactionId": {fmt.Sprintf("frodo-%s", uuid.New().String())},
	}
	if params.resource["apiVersion"] != "" {
		req.Header.Set("Accept-API-Version", params.resource["apiVersion"])
	}
	if params.authenticate && !state.getUseBearerTokenForAmApis() && state.CookieName != "" && state.getCookieValue() != "" {
		req.Header.Set(state.CookieName, state.getCookieValue())
	}
	if params.authenticate && state.getUseBearerTokenForAmApis() && state.getBearerToken().AccessToken != "" {
		req.Header.Set("Authorization:", fmt.Sprintf("Bearer %s", state.getBearerToken().AccessToken))
	}
	for headerName, headerValue := range params.headers {
		req.Header.Set(headerName, strings.Join(headerValue, ", "))
	}
	return req
}

type AccessTokenMetaType struct {
	AccessToken string `json:"access_token"`
	IdToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	from_cache  bool
}

type EnvInfoInterface struct {
	BackupRegion          string   `json:"backupRegion"`
	ConfigPromotionDone   bool     `json:"config_promotion_done"`
	Immutable             bool     `json:"immutable"`
	IPAddresses           []string `json:"ipAddresses"`
	Locked                bool     `json:"locked"`
	PlaceholderManagement string   `json:"placeholder_management"`
	PromotionTierInfo     struct {
		TierDisplayName      string   `json:"tierDisplayName"`
		Tiers                []string `json:"tiers"`
		UpperTierDisplayName any      `json:"upperTierDisplayName"`
		LowerTierDisplayName any      `json:"lowerTierDisplayName"`
	} `json:"promotionTierInfo"`
	Region string `json:"region"`
	Tier   string `json:"tier"`
}

func (frodo Frodo) getSaBearerToken() (AccessTokenMetaType, error) {
	state := frodo.State
	frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getSaBearerToken: start"))
	token := AccessTokenMetaType{}
	if state.getUseTokenCache() && (frodo.hasSaBearerToken()) {
		token, err := frodo.readSaBearerToken()
		if err != nil {
			frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getSaBearerToken: end [failed cache read]"))
		} else {
			token.from_cache = true
		}
	}
	if token == (AccessTokenMetaType{}) {
		token = frodo.getFreshSaBearerToken()
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getSaBearerToken: end [fresh]"))
		token.from_cache = false
	}
	if state.getUseTokenCache() {
		frodo.saveSaBearerToken(token)
	}
	return token, nil
}

func (frodo Frodo) saveSaBearerToken(token AccessTokenMetaType) {
	//todo
}

func (frodo Frodo) getFreshSaBearerToken() AccessTokenMetaType {
	state := frodo.State
	frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getFreshSaBearerToken: start"))
	saId := state.getServiceAccountId()
	saJwk := state.getServiceAccountJwk()
	payload, _ := frodo.createPayload(saId, state.getHost())
	signedJWT := createSignedJwtToken(payload, saJwk)
	scope := state.ServiceAccountScope
	if scope == "" {
		scope = constants.ServiceAccountScopes
	}
	bodyFormData := fmt.Sprintf("assertion=%s&client_id=service-account&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&scope=%s", url.QueryEscape(signedJWT), url.QueryEscape(scope))
	var data = frodo.accessToken(HTTPRequestParams{
		url:  state.getHost(),
		body: bodyFormData,
		headers: http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
		method: http.MethodPost,
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, _ := client.Do(&data)
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
	}
	var responseObject AccessTokenMetaType = AccessTokenMetaType{}
	if resp.StatusCode != http.StatusOK {
		var objmap map[string]string
		err = json.Unmarshal(responseData, &objmap)
		invalidScopes := strings.Split(strings.TrimSpace(objmap["error_description"][39:]), ",")
		finalScopes := []string{}

		for _, el := range strings.Split(scope, " ") {
			if !contains(invalidScopes, el) {
				finalScopes = append(finalScopes, el)
			}
		}
		bodyFormData := fmt.Sprintf("assertion=%s&client_id=service-account&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&scope=%s", url.QueryEscape(signedJWT), url.QueryEscape(strings.Join(finalScopes, " ")))
		var data = frodo.accessToken(HTTPRequestParams{
			url:  state.getHost(),
			body: bodyFormData,
			headers: http.Header{
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			method: http.MethodPost,
		})
		client := &http.Client{
			Timeout: time.Second * 10,
		}
		resp, _ := client.Do(&data)
		defer resp.Body.Close()
		responseData, err := io.ReadAll(resp.Body)
		if err != nil {
		}
		err = json.Unmarshal(responseData, &responseObject)
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getFreshSaBearerToken: end"))
		return responseObject
	} else {
		err = json.Unmarshal(responseData, &responseObject)
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getFreshSaBearerToken: end"))
		return responseObject
	}
}

func contains(slice []string, item string) bool {
	for _, el := range slice {
		if el == item {
			return true
		}
	}
	return false
}

func createSignedJwtToken(tok jwt.Token, jwks string) string {
	privkey, err := jwk.ParseKey([]byte(jwks))
	if err != nil {
		return ""
	}
	sign, err := jwt.Sign(tok, jwa.RS256, privkey)
	if err != nil {
		return ""
	}
	return string(sign[:])
}

func (frodo Frodo) readSaBearerToken() (AccessTokenMetaType, error) {
	token, err := frodo.readToken(TokenParam{tokenType: "saBearer"})
	return token, err
}

type TokenParam struct {
	tokenType string
}

func (frodo Frodo) hasSaBearerToken() bool {
	return frodo.hasToken(TokenParam{tokenType: "saBearer"})
}

func (frodo Frodo) hasToken(param TokenParam) bool {
	frodo.DebugMessage(fmt.Sprintf("TokenCacheOps.hasToken: start [tokenType=%s]", param.tokenType))
	_, err := frodo.readToken(param)
	if err != nil {
		frodo.DebugMessage(fmt.Sprintf("TokenCacheOps.hasToken: end [has $%s token: false", param.tokenType))
		return false
	}
	frodo.DebugMessage(fmt.Sprintf("TokenCacheOps.hasToken: end [has $%s token: true", param.tokenType))
	return true
}

func (frodo Frodo) readToken(param TokenParam) (AccessTokenMetaType, error) {
	//todo
	return AccessTokenMetaType{}, errors.New("empty token")
}

func (frodo Frodo) createPayload(serviceAccountId string, host string) (jwt.Token, error) {
	u := parseUrl(host)
	port := "80"
	if u.Protocol == "https" {
		port = "443"
	}
	aud := fmt.Sprintf("%s://%s:%s%s/oauth2/access_token", u.Protocol, u.Host, port, u.Pathname)

	tok, err := jwt.NewBuilder().
		Issuer(serviceAccountId).
		Subject(serviceAccountId).
		Audience([]string{aud}).
		Expiration(time.Now()).
		Claim("jti", uuid.New().String()).
		Build()
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func (frodo Frodo) getManagedObject(params ManagedObjectParams) ServiceAccountType {
	fieldsParam := "_fields=" + strings.Join(params.Fields, ",")

	urlString := fmt.Sprintf(constants.ManagedObjectByIdURLTemplate+"?%s", frodo.getIdmBaseUrl(), params.Type, params.Id, fieldsParam)
	data := frodo.generateIdmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "GET",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	var responseObject ServiceAccountType = ServiceAccountType{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject
}

func (frodo Frodo) getIdmBaseUrl() string {
	state := frodo.State
	if idmHost := state.getIdmHost(); idmHost != "" {
		return idmHost
	}
	return fmt.Sprintf("%s/openidm", frodo.getHostOnlyUrl())
}

func (frodo Frodo) getHostOnlyUrl() string {
	state := frodo.State
	parsedUrl, _ := url.Parse(state.getHost())
	return fmt.Sprintf("%s://%s", parsedUrl.Scheme, parsedUrl.Host)
}

func (frodo Frodo) getCloudInfo() EnvInfoInterface {
	info, _ := frodo.getEnvInfo()
	return info
}

func (frodo Frodo) getEnvInfo() (EnvInfoInterface, error) {
	urlString := fmt.Sprintf(constants.EnvInfoURLTemplate, frodo.getHostOnlyUrl())
	data := frodo.generateAmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "GET",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body) // response body is []byte
	var responseObject EnvInfoInterface
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

func (frodo Frodo) checkAndHandle2FA(params CheckAndHandle2FAParams) CallbackHandlerResponse {
	state := frodo.State
	payload := params.payload
	frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: start")
	if payload["callbacks"] != nil {
		for _, callback := range payload["callbacks"].([]interface{}) {
			callbackType := callback.(map[string]interface{})["type"].(string)
			if callbackType == "SelectIdPCallback" {
				frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: Admin federation enabled. Allowed providers:")
				localAuth := false
				p := callback.(map[string]interface{})["output"].([]interface{})[0]
				q := p.(map[string]interface{})["value"].([]interface{})
				for _, value := range q {
					r := value.(map[string]interface{})["provider"]
					if r == "localAuthentication" {
						localAuth = true
					}
				}
				if localAuth {
					frodo.DebugMessage("local auth allowed")
					p1 := callback.(map[string]interface{})["input"].([]interface{})[0]
					p1.(map[string]interface{})["value"] = "localAuthentication"
				} else {
					frodo.DebugMessage("local auth NOT allowed")
				}
			}
			if callbackType == "HiddenValueCallback" {
				p := callback.(map[string]interface{})["input"].([]interface{})[0]
				q := p.(map[string]interface{})["value"].(string)
				if strings.Contains(q, "skip") {
					q = "Skip"
				}
				if strings.Contains(q, "webAuthnOutcome") {
					frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: end [need2fa=true, unsupported Factor: webauthn]")
					return CallbackHandlerResponse{
						NextStep:  false,
						Need2FA:   true,
						Factor:    "WebAuthN",
						Supported: false,
						Payload:   payload,
					}
				}
			}
			if callbackType == "NameCallback" {
				o := callback.(map[string]interface{})["output"].([]interface{})[0]
				v := o.(map[string]interface{})["value"].(string)
				if strings.Contains(v, "code") {
					frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: need2fa=true, skippable=false")
					if params.OTPCallbackHandler == nil {
						panic("2fa required but no otpCallback function provided.")
					}
					callback = params.OTPCallbackHandler(params.payload)
					frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: end [need2fa=true, skippable=false, Factor=Code]")
					return CallbackHandlerResponse{
						NextStep:  true,
						Need2FA:   true,
						Factor:    "Code",
						Supported: true,
						Payload:   payload,
					}
				} else {
					p := callback.(map[string]interface{})["input"].([]interface{})[0]
					p.(map[string]interface{})["value"] = state.getUsername()
				}
			}
			if callbackType == "PasswordCallback" {
				p := callback.(map[string]interface{})["input"].([]interface{})[0]
				p.(map[string]interface{})["value"] = state.getPassword()
			}
		}
		frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: end [need2fa=false]")
		return CallbackHandlerResponse{
			NextStep:  true,
			Need2FA:   false,
			Factor:    "None",
			Supported: true,
			Payload:   payload,
		}
	}
	frodo.DebugMessage("AuthenticateOps.checkAndHandle2FA: end [need2fa=false]")
	return CallbackHandlerResponse{
		NextStep:  false,
		Need2FA:   false,
		Factor:    "None",
		Supported: true,
		Payload:   payload,
	}
}

type ParsedUrl struct {
	Hash        string
	Host        string
	Hostname    string
	Href        string
	Origin      string
	Pathname    string
	Port        string
	Protocol    string
	Search      string
	Username    string
	Password    string
	SearchParam map[string]string
}

func parseUrl(href string) ParsedUrl {
	m := regexp.MustCompile(`^(([^:/?#]+):?(?:\/\/((?:([^/?#:]*):([^/?#:]*)@)?([^/?#:]*)(?::([^/?#:]*))?)))?([^?#]*)(\?[^#]*)?(#.*)?$`).FindStringSubmatch(href)

	r := ParsedUrl{
		Hash:        getString(m, 10),
		Host:        getString(m, 3),
		Hostname:    getString(m, 6),
		Href:        getString(m, 0),
		Origin:      getString(m, 1),
		Pathname:    getString(m, 8),
		Port:        getString(m, 7),
		Protocol:    getString(m, 2),
		Search:      getString(m, 9),
		Username:    getString(m, 4),
		Password:    getString(m, 5),
		SearchParam: make(map[string]string),
	}

	if len(r.Protocol) == 2 {
		r.Protocol = "file:///" + strings.ToUpper(r.Protocol)
		r.Origin = r.Protocol + "//" + r.Host
	}

	if len(r.Search) > 2 {
		query := r.Search
		if strings.HasPrefix(query, "?") {
			query = query[1:]
		}
		vars := strings.Split(query, "&")
		for _, v := range vars {
			pair := strings.SplitN(v, "=", 2)
			if len(pair) == 2 {
				r.SearchParam[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1])
			}
		}
	}

	r.Href = r.Origin + r.Pathname + r.Search + r.Hash
	return r
}

func getString(m []string, index int) string {
	if index < len(m) {
		return m[index]
	}
	return ""
}

func decodeURIComponent(encoded string) string {
	decoded, _ := url.QueryUnescape(encoded)
	return decoded
}

func (frodo Frodo) getUserBearerToken() AccessTokenMetaType {
	state := frodo.State
	frodo.DebugMessage("AuthenticateOps.getUserBearerToken: start")
	token := AccessTokenMetaType{}
	if state.getUseTokenCache() && (state.hasUserBearerToken()) {
		token, err := frodo.readUserBearerToken()
		if err != nil {
			frodo.DebugMessage("AuthenticateOps.getUserBearerToken: end [failed cache read]")
		} else {
			token.from_cache = true
			frodo.DebugMessage("AuthenticateOps.getUserBearerToken: end [cached]")
		}
	}
	if token == (AccessTokenMetaType{}) {
		token = frodo.getFreshUserBearerToken()
		//todo This needs to be enabled for accessing API
		//state.setUseBearerTokenForAmApis(true)
		token.from_cache = false
		frodo.DebugMessage("AuthenticateOps.getUserBearerToken: end [fresh]")
	}
	if state.getUseTokenCache() {
		frodo.saveUserBearerToken()
	}
	return token

}

func (frodo Frodo) readUserBearerToken() (AccessTokenMetaType, error) {
	//todo
	return AccessTokenMetaType{}, nil
}

func (frodo Frodo) saveUserBearerToken() bool {
	//todo
	frodo.DebugMessage("TokenCacheOps.saveUserBearerToken: start")
	frodo.DebugMessage("TokenCacheOps.saveUserBearerToken: end")
	return true
}

func (frodo Frodo) getFreshUserBearerToken() AccessTokenMetaType {
	state := frodo.State
	frodo.DebugMessage("AuthenticateOps.getAccessTokenForUser: start")
	verifier, _ := randomBytes(32)
	encodedVerifier := encodeBase64Url(verifier)
	hash := sha256.New()
	hash.Write([]byte(encodedVerifier))
	challenge := encodeBase64Url(hash.Sum(nil))
	challengeMethod := "S256"
	redirectUri, _ := url.Parse(state.getHost())
	redirectUri.Path = state.getAdminClientRedirectUri()
	authCode := frodo.getAuthCode(redirectUri.String(), challenge, challengeMethod)
	bodyFormData := url.Values{}
	headers := http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
	}
	if state.getDeploymentType() == constants.CloudDeploymentTypeKey {
		headers.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(adminClientId+":"+adminClientPassword)))
		bodyFormData.Set("redirect_uri", redirectUri.String())
		bodyFormData.Set("grant_type", "authorization_code")
		bodyFormData.Set("code", authCode)
		bodyFormData.Set("code_verifier", encodedVerifier)
	} else {
		bodyFormData.Set("client_id", adminClientId)
		bodyFormData.Set("redirect_uri", redirectUri.String())
		bodyFormData.Set("grant_type", "authorization_code")
		bodyFormData.Set("code", authCode)
		bodyFormData.Set("code_verifier", encodedVerifier)
	}
	var data = frodo.accessToken(HTTPRequestParams{
		url:     state.getHost(),
		body:    bodyFormData.Encode(),
		headers: headers,
		method:  http.MethodPost,
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, _ := client.Do(&data)
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
	}
	var responseObject AccessTokenMetaType
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject
}

func (frodo Frodo) getAuthCode(redirectUri string, codeChallenge string, codeChallengeMethod string) string {
	state := frodo.State
	var scopes string
	if state.getDeploymentType() == constants.CloudDeploymentTypeKey {
		scopes = constants.CloudAdminScopes
	} else {
		scopes = constants.ForgeopsAdminScopes
	}
	bodyFormData := url.Values{}
	bodyFormData.Set("redirect_uri", redirectUri)
	bodyFormData.Set("scope", scopes)
	bodyFormData.Set("response_type", "code")
	bodyFormData.Set("client_id", adminClientId)
	bodyFormData.Set("csrf", state.getCookieValue())
	bodyFormData.Set("decision", "allow")
	bodyFormData.Set("code_challenge", codeChallenge)
	bodyFormData.Set("code_challenge_method", codeChallengeMethod)
	var data = frodo.authorize(HTTPRequestParams{
		url:  state.getHost(),
		body: bodyFormData.Encode(),
		headers: http.Header{
			state.CookieName: {state.getCookieValue()},
			"Content-Type":   {"application/x-www-form-urlencoded"},
		},
		method: http.MethodPost,
	})
	client := &http.Client{
		Timeout: time.Second * 10,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(&data)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode > 399 {
		panic("Incorrect response")
	}
	parse, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		panic(err)
	}
	return parse.Query().Get("code")
}
