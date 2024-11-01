package frodo

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
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

type Params struct {
	Host, User, Pass        string
	Realm                   string
	DeploymentType          string
	AllowInsecureConnection bool
	Debug                   bool
	Curlirize               bool
	ServiceAccountId        string
	ServiceAccountJwk       string
}

type ImFrodo interface {
	Login()
	GetInfo() PlatformInfo
	state() State
}

type State struct {
	Host     string
	Username string
	Password string
	Realm    string

	ServiceAccountId              string
	ServiceAccountJwk             string
	DeploymentType                string
	IdmHost                       string
	AdminClientId                 string
	AdminClientRedirectUri        string
	AuthenticationService         string
	AllowInsecureConnection       string
	AuthenticationHeaderOverrides string
	ServiceAccountScope           string
	CookieName                    string
	UseBearerTokenForAmApis       bool
	BearerToken                   AccessTokenMetaType
	getUseBearerTokenForAmApis    bool
	UseTokenCache                 bool
	UserSessionTokenMeta          UserSessionMetaType
	AmVersion                     interface{}
	BearerTokenMeta               AccessTokenMetaType
	IDMHost                       string
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

func (frodo Frodo) getUserBearerToken() AccessTokenMetaType {
	return frodo.State.BearerToken
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
		Host:                 state.Host,
		AmVersion:            frodo.getAmVersion(),
		AuthenticatedSubject: frodo.getAuthenticatedSubject(),
		DeploymentType:       state.DeploymentType,
		CookieName:           state.CookieName,
		SessionToken:         state.getCookieValue(),
	}
	if state.BearerToken != (AccessTokenMetaType{}) {
		info.BearerToken = state.BearerToken.AccessToken
	}
	if state.DeploymentType == CLOUD_DEPLOYMENT_TYPE_KEY {
		info.CloudInfo = frodo.getCloudInfo()
	}
	return info
}

func CreateInstanceWithAdminAccount(p Params) (ImFrodo, error) {
	instance := Frodo{
		State: &State{
			Host:     p.Host,
			Username: p.User,
			Password: p.Pass,
			Realm:    p.Realm,
		},
	}
	return instance, nil
}

func CreateInstanceWithServiceAccount(p Params) (ImFrodo, error) {
	instance := Frodo{
		State: &State{
			Host:              p.Host,
			ServiceAccountId:  p.ServiceAccountId,
			ServiceAccountJwk: p.ServiceAccountJwk,
			Realm:             p.Realm,
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

func (state State) HasUserSessionToken() bool {
	return true
}

func (state State) getAuthenticationService() string {
	// || process.env.FRODO_AUTHENTICATION_SERVICE
	return state.AuthenticationService
}

func (state State) getCookieValue() string {
	return state.UserSessionTokenMeta.tokenId
}

func (state State) setBearerTokenMeta(token AccessTokenMetaType) {
	state.BearerToken = token
}

func (state State) getCurrentRealmPath() string {
	return getRealmPath(state.Realm)
}

func (state State) getUseTokenCache() bool {
	// todo process.env.FRODO_NO_CACHE
	return state.UseTokenCache
}

func (state State) getIdmHost() string {
	//todo || process.env.FRODO_IDM_HOST
	//if idmHost := state.getIdmHost(); idmHost != "" {
	//		return process.env.FRODO_IDM_HOST
	//	}
	return state.IDMHost
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

func loadConnectionProfile(state State) bool {
	return false
}
func getConnectionProfile(state State) bool {
	return false
}
func determineCookieName(state State) bool {
	return false
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
	//if state.Username == "" && state.Password == "" && state.ServiceAccountId != "" && state.ServiceAccountJwk != "" {
	//	usingConnectionProfile = frodo.loadConnectionProfile()
	//	if state.DeploymentType != "" && !slices.Contains(DEPLOYMENT_TYPES, state.DeploymentType) {
	//		errorString := fmt.Sprintf("Unsupported deployment type: %s", state.DeploymentType)
	//		panic(errorString)
	//	}
	//}
	if !isValidUrl(state.Host) {
		conn, _ := frodo.getConnectionProfile()
		state.Host = conn.tenant
		state.AllowInsecureConnection = conn.allowInsecureConnection
		state.DeploymentType = conn.deploymentType

		// fail fast if deployment type not applicable
		if state.DeploymentType != "" && !slices.Contains(DEPLOYMENT_TYPES, state.DeploymentType) {
			errorString := fmt.Sprintf("Unsupported deployment type: %s", state.DeploymentType)
			panic(errorString)
		}
	}
	state.CookieName = frodo.determineCookieName()
	// use service account to login?
	if !forceLoginAsUser && (state.DeploymentType == CLOUD_DEPLOYMENT_TYPE_KEY || state.DeploymentType == "") && state.ServiceAccountId != "" && state.ServiceAccountJwk != "" {
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getTokens: Authenticating with service account %s", state.ServiceAccountId))
		//try {
		token, err := frodo.getSaBearerToken()
		if err != nil {
		}
		if token != (AccessTokenMetaType{}) {
			state.BearerToken = token
		}

		if usingConnectionProfile && !token.from_cache {
			frodo.saveConnectionProfile(SaveConnectionProfileParams{host: state.Host})
		}
		state.UseBearerTokenForAmApis = true
		frodo.determineDeploymentTypeAndDefaultRealmAndVersion()
		if state.DeploymentType != "" && !slices.Contains(DEPLOYMENT_TYPES, state.DeploymentType) {
			panic(fmt.Sprintf("Unsupported deployment type '%s'", state.DeploymentType))
		}
	} else if state.Username != "" && state.Password != "" {
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.getTokens: Authenticating with user account %s", state.Username))
		token := frodo.getUserSessionToken(frodo.CallbackHandler())
		if token.tokenId != "" {
			state.UserSessionTokenMeta = token
		}

		if usingConnectionProfile && !token.from_cache {
			frodo.saveConnectionProfile(SaveConnectionProfileParams{host: state.Host})
		}
		frodo.determineDeploymentTypeAndDefaultRealmAndVersion()
		//
		//// fail if deployment type not applicable
		if state.DeploymentType != "" && !slices.Contains(DEPLOYMENT_TYPES, state.DeploymentType) {
			panic(fmt.Sprintf("Unsupported deployment type '%s'", state.DeploymentType))
		}
		if state.getCookieValue() != "" && (state.DeploymentType == CLOUD_DEPLOYMENT_TYPE_KEY || state.DeploymentType == FORGEOPS_DEPLOYMENT_TYPE_KEY) {
			accessToken := frodo.getUserBearerToken()
			if accessToken != (AccessTokenMetaType{}) {
				state.setBearerTokenMeta(accessToken)
			}
		}
	} else {
		panic("Incomplete or no credentials")
	}
	if state.getCookieValue() != "" || (state.UseBearerTokenForAmApis && state.BearerToken.AccessToken != "") {
		if state.BearerTokenMeta.from_cache {
			frodo.VerboseMessage("Using cached bearer token.")
		}
		if state.UseBearerTokenForAmApis && state.UserSessionTokenMeta.from_cache {
			frodo.VerboseMessage("Using cached session token.")
		}
	}
	frodo.scheduleAutoRefresh(forceLoginAsUser, autoRefresh)
	tokens := Tokens{
		bearerToken:      state.BearerTokenMeta,
		userSessionToken: state.UserSessionTokenMeta,
		subject:          frodo.getLoggedInSubject(),
		host:             state.Host,
	}
	if state.Realm != "" {
		tokens.realm = state.Realm
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
	return frodo.loadConnectionProfileByHost(frodo.State.Host)
}

func (frodo *Frodo) loadConnectionProfileByHost(host string) bool {
	conn, err := frodo.getConnectionProfileByHost(host)
	if err != nil {
		return false
	}
	state := frodo.State
	state.Host = conn.tenant
	if state.IdmHost == "" {
		state.IdmHost = conn.idmHost
	}
	state.AllowInsecureConnection = conn.allowInsecureConnection
	if state.DeploymentType == "" {
		state.DeploymentType = conn.deploymentType
	}
	if state.AdminClientId == "" {
		state.AdminClientId = conn.adminClientId
	}
	if state.AdminClientRedirectUri == "" {
		state.AdminClientRedirectUri = conn.adminClientRedirectUri
	}
	state.Username = conn.username
	state.Password = conn.password
	state.AuthenticationService = conn.authenticationService
	state.AuthenticationHeaderOverrides = conn.authenticationHeaderOverrides
	state.ServiceAccountId = conn.svcacctId
	state.ServiceAccountJwk = conn.svcacctJwk
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
	return frodo.getConnectionProfileByHost(frodo.State.Host)
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
	urlString := fmt.Sprintf(ServerInfoUrlTemplate, frodo.State.Host, "*")
	data := frodo.generateAmApi(HTTPRequestParams{
		resource: map[string]string{
			"apiVersion": ServerInfoApiVersion,
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
	if state.UseBearerTokenForAmApis && state.BearerToken.AccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.BearerToken.AccessToken))
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
	if !state.UseBearerTokenForAmApis && state.CookieName != "" && state.getCookieValue() != "" {
		req.Header.Set(state.CookieName, state.getCookieValue())
	}
	if state.UseBearerTokenForAmApis && state.BearerToken.AccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.BearerToken.AccessToken))
	}
	for headerName, headerValue := range params.headers {
		req.Header.Set(headerName, strings.Join(headerValue, ", "))
	}
	return req
}

type FreshUserSessionTokenParams struct {
	otpCallbackHandler interface{}
}

func (frodo Frodo) getUserSessionToken(handler func()) UserSessionMetaType {
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
			otpCallbackHandler: frodo.OTPCallbackHandler(),
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

func (frodo Frodo) CallbackHandler() func() {
	return func() {
		// fmt.Println("CallbackHandler")
	}
}
func (frodo Frodo) OTPCallbackHandler() func() {
	return func() {
		//fmt.Println("OTPCallbackHandler")
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

func (frodo Frodo) getFreshUserSessionToken(params FreshUserSessionTokenParams) UserSessionMetaType {
	frodo.DebugMessage("AuthenticateOps.getFreshUserSessionToken: start")
	state := frodo.State
	config := StepConfig{
		body: "{}",
		headers: http.Header{
			"X-OpenAM-Username": {state.Username},
			"X-OpenAM-Password": {state.Password},
		},
	}
	response, err := frodo.Step(config)
	if err != nil {
		panic(err)
	}
	//
	//let skip2FA = null;
	//let steps = 0;
	//const maxSteps = 3;
	//do {
	//	skip2FA = checkAndHandle2FA({
	//	payload: response,
	//	otpCallbackHandler: otpCallbackHandler,
	//	state,
	//});
	//
	//	// throw exception if 2fa required but factor not supported by frodo (e.g. WebAuthN)
	//	if (!skip2FA.supported) {
	//	throw new Error(`Unsupported 2FA factor: ${skip2FA.factor}`);
	//}
	//
	//	if (skip2FA.nextStep) {
	//	steps++;
	//	response = await step({ body: skip2FA.payload, state });
	//}
	//
	sessionInfo := SessionInfoType{}
	if response["tokenId"] != "" {
		response["from_cache"] = false
		// get session expiration
		sessionInfo = frodo.getSessionInfo(
			SessionInfoParams{
				tokenId: response["tokenId"].(string),
			},
		)
	}
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
	////}
	//} while (skip2FA.nextStep && steps < maxSteps);
	//frodo.DebugMessage("AuthenticateOps.getFreshUserSessionToken: end [no session]")
	//return UserSessionMetaType{}
}

func (frodo Frodo) saveUserSessionToken(token UserSessionMetaType) {
	frodo.DebugMessage("TokenCacheOps.saveUserSessionToken: start")
	frodo.DebugMessage("TokenCacheOps.saveUserSessionToken: end")
}

func (frodo Frodo) Step(config StepConfig) (map[string]interface{}, error) {
	state := frodo.State
	var urlString string
	if config.service != "" || state.getAuthenticationService() != "" {
		urlString = fmt.Sprintf(AuthenticateWithServiceUrlTemplate, state.Host, getRealmPath(config.realm), config.service)
	} else {
		urlString = fmt.Sprintf(AuthenticateUrlTemplate, state.Host, getRealmPath(config.realm))
	}
	var data = frodo.generateAmApi(HTTPRequestParams{
		resource: map[string]string{
			"apiVersion": ServerInfoApiVersion,
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
	urlString := fmt.Sprintf(SessionInfoURLTemplate, state.Host, frodo.getCurrentRealmPath())
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
	return getRealmPath(frodo.State.Realm)
}

func (frodo Frodo) saveConnectionProfile(params SaveConnectionProfileParams) {
	panic("implement me")
}

func (frodo Frodo) determineDeploymentTypeAndDefaultRealmAndVersion() {
	state := frodo.State
	frodo.DebugMessage("AuthenticateOps.determineDeploymentTypeAndDefaultRealmAndVersion: start")
	state.DeploymentType = frodo.determineDeploymentType()
	frodo.determineDefaultRealm()
	frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentTypeAndDefaultRealmAndVersion: realm=%s, type=%s", state.Realm, state.DeploymentType))
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
	deploymentType := state.DeploymentType
	switch deploymentType {

	case CLOUD_DEPLOYMENT_TYPE_KEY:
		adminClientId := state.AdminClientId
		if adminClientId == "" {
			adminClientId = fidcClientId
		}
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
		return deploymentType
	case FORGEOPS_DEPLOYMENT_TYPE_KEY:
		adminClientId := state.AdminClientId
		if adminClientId == "" {
			adminClientId = forgeopsClientId
		}
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
		return deploymentType
	case CLASSIC_DEPLOYMENT_TYPE_KEY:
		frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", deploymentType))
		return deploymentType
	default:
		// if we are using a service account, we know it's cloud
		if state.UseBearerTokenForAmApis {
			frodo.DebugMessage(fmt.Sprintf("AuthenticateOps.determineDeploymentType: end [type=%s]", CLOUD_DEPLOYMENT_TYPE_KEY))
			return CLOUD_DEPLOYMENT_TYPE_KEY
		}
		verifier, _ := randomBytes(32)
		encodedVerifier := encodeBase64Url(verifier)
		hash := sha256.New()
		hash.Write([]byte(encodedVerifier))
		challenge := encodeBase64Url(hash.Sum(nil))
		challengeMethod := "S256"
		redirectUri, _ := url.Parse(state.Host)
		redirectUri.Path = RedirectUrlTemplate
		bodyFormData := fmt.Sprintf("redirect_uri=%s&scope=%s&response_type=code&client_id=%s&csrf=%s&decision=allow&code_challenge=%s&code_challenge_method=%s", url.QueryEscape(redirectUri.String()), url.QueryEscape(CloudAdminScopes), url.QueryEscape(fidcClientId), url.QueryEscape(cookieValue), url.QueryEscape(challenge), url.QueryEscape(challengeMethod))
		deploymentType = CLASSIC_DEPLOYMENT_TYPE_KEY
		var data = frodo.authorize(HTTPRequestParams{
			url:  state.Host,
			body: bodyFormData,
			headers: http.Header{
				state.CookieName: {state.getCookieValue()},
				"Content-Type":   {"application/x-www-form-urlencoded"},
			},
			method: http.MethodPost,
		})
		client := &http.Client{
			Timeout: time.Second * 10,
		}
		resp, _ := client.Do(&data)
		if resp.StatusCode == 302 && strings.Index(resp.Header.Get("Location"), "code=") > -1 {
			frodo.VerboseMessage("ForgeRock Identity Cloud deployment detected.")
		} else {
			bodyFormData = fmt.Sprintf("redirect_uri=%s&scope=%s&response_type=code&client_id=%s&csrf=%s&decision=allow&code_challenge=%s&code_challenge_method=%s", url.QueryEscape(redirectUri.String()), url.QueryEscape(ForgeopsAdminScopes), url.QueryEscape(forgeopsClientId), url.QueryEscape(cookieValue), url.QueryEscape(challenge), url.QueryEscape(challengeMethod))
			var data = frodo.authorize(HTTPRequestParams{
				url:  state.Host,
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
				adminClientId := state.AdminClientId
				if adminClientId == "" {
					adminClientId = forgeopsClientId
				}
				frodo.VerboseMessage("ForgeOps deployment detected.")
				deploymentType = FORGEOPS_DEPLOYMENT_TYPE_KEY
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
	urlString := fmt.Sprintf(ServerInfoUrlTemplate, state.Host, "version")
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
	if state.Realm == "" {
		state.Realm = DEPLOYMENT_TYPE_REALM_MAP[state.DeploymentType]
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
	serviceAccountId string
}

func (frodo Frodo) getAuthenticatedSubject() string {
	state := frodo.State
	var subjectString = fmt.Sprintf("%s (User)", state.Username)
	if state.UseBearerTokenForAmApis {
		serviceAccount := frodo.getServiceAccount(ServiceAccountParams{
			serviceAccountId: state.ServiceAccountId,
		})
		subjectString = fmt.Sprintf("%s[%s] (Service Account)", serviceAccount.Name, state.ServiceAccountId)
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

func (frodo Frodo) getServiceAccount(params ServiceAccountParams) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.getServiceAccount: start")
	serviceAccount := frodo.getManagedObject(ManagedObjectParams{
		Type:   MOType,
		Id:     params.serviceAccountId,
		Fields: []string{"*"},
	})
	frodo.DebugMessage(fmt.Sprintf("%+v", serviceAccount))
	frodo.DebugMessage("ServiceAccountOps.getServiceAccount: end")
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
	urlString := fmt.Sprintf(AuthorizeUrlTemplate, params.url, frodo.State.getCurrentRealmPath())
	params.url = urlString
	return frodo.generateOauth2Api(params)
}

func (frodo Frodo) accessToken(params HTTPRequestParams) http.Request {
	urlString := fmt.Sprintf(AccessTokenUrlTemplate, params.url, frodo.State.getCurrentRealmPath())
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
	if params.authenticate && !state.UseBearerTokenForAmApis && state.CookieName != "" && state.getCookieValue() != "" {
		req.Header.Set(state.CookieName, state.getCookieValue())
	}
	if params.authenticate && state.getUseBearerTokenForAmApis && state.BearerToken.AccessToken != "" {
		req.Header.Set("Authorization:", fmt.Sprintf("Bearer %s", state.BearerToken.AccessToken))
	}
	for headerName, headerValue := range params.headers {
		req.Header.Set(headerName, strings.Join(headerValue, ", "))
	}
	return req
}

type AccessTokenMetaType struct {
	AccessToken string `json:"access_token"`
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
	saId := state.ServiceAccountId
	saJwk := state.ServiceAccountJwk
	payload, _ := frodo.createPayload(saId, state.Host)
	signedJWT := createSignedJwtToken(payload, saJwk)
	scope := state.ServiceAccountScope
	if scope == "" {
		scope = ServiceAccountDefaultScopes
	}
	bodyFormData := fmt.Sprintf("assertion=%s&client_id=service-account&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&scope=%s", url.QueryEscape(signedJWT), url.QueryEscape(scope))
	var data = frodo.accessToken(HTTPRequestParams{
		url:  state.Host,
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
			url:  state.Host,
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

	urlString := fmt.Sprintf(ManagedObjectByIdURLTemplate+"?%s", frodo.getIdmBaseUrl(), params.Type, params.Id, fieldsParam)
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
	parsedUrl, _ := url.Parse(state.Host)
	return fmt.Sprintf("%s://%s", parsedUrl.Scheme, parsedUrl.Host)
}

func (frodo Frodo) getCloudInfo() EnvInfoInterface {
	info, _ := frodo.getEnvInfo()
	return info
}

func (frodo Frodo) getEnvInfo() (EnvInfoInterface, error) {
	urlString := fmt.Sprintf(EnvInfoURLTemplate, frodo.getHostOnlyUrl())
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
