package frodo

import (
	"github.com/darkedges/go-frodo-lib/constants"
)

type State struct {
	host     string
	username string
	password string
	realm    string

	serviceAccountId              string
	serviceAccountJwk             string
	deploymentType                string
	IdmHost                       string
	AdminClientId                 string
	AdminClientRedirectUri        string
	authenticationService         string
	AllowInsecureConnection       string
	AuthenticationHeaderOverrides string
	ServiceAccountScope           string
	CookieName                    string
	bearerToken                   AccessTokenMetaType
	useBearerTokenForAmApis       bool
	UseTokenCache                 bool
	userSessionToken              UserSessionMetaType
	AmVersion                     interface{}
	IDMHost                       string
	OTPSecret                     string
	DebugHandler                  func(string)
	VerboseHandler                func(string)
}

func (state *State) SetDebugHandler(debug func(string)) {
	state.DebugHandler = debug
}

func (state *State) SetVerboseHandler(verbose func(string)) {
	state.VerboseHandler = verbose
}

func (state *State) getDeploymentType() string {
	return state.deploymentType
}

func (state *State) setDeploymentType(deploymentType string) {
	state.deploymentType = deploymentType
}

func (state *State) getHost() string {
	return state.host
}

func (state *State) setHost(host string) {
	state.host = host
}

func (state *State) getRealm() string {
	return state.realm
}

func (state *State) setRealm(realm string) {
	state.realm = realm
}

func (state *State) getServiceAccountId() string {
	return state.serviceAccountId
}

func (state *State) setServiceAccountId(serviceAccountId string) {
	state.serviceAccountId = serviceAccountId
}

func (state *State) getServiceAccountJwk() string {
	return state.serviceAccountJwk
}

func (state *State) setServiceAccountJwk(serviceAccountJwk string) {
	state.serviceAccountJwk = serviceAccountJwk
}

func (state *State) getUsername() string {
	return state.username
}

func (state *State) setUsername(username string) {
	state.username = username
}

func (state *State) getPassword() string {
	return state.password
}

func (state *State) setPassword(password string) {
	state.password = password
}

func (state *State) getBearerToken() AccessTokenMetaType {
	return state.bearerToken
}

func (state *State) setBearerToken(bearerToken AccessTokenMetaType) {
	state.bearerToken = bearerToken
}

func (state *State) getUseBearerTokenForAmApis() bool {
	return state.useBearerTokenForAmApis
}

func (state *State) setUseBearerTokenForAmApis(useBearerTokenForAmApis bool) {
	state.useBearerTokenForAmApis = useBearerTokenForAmApis
}

func (state State) HasUserSessionToken() bool {
	return true
}

func (state State) getAuthenticationService() string {
	// || process.env.FRODO_AUTHENTICATION_SERVICE
	return state.authenticationService
}
func (state *State) setAuthenticationService(authenticationService string) {
	state.authenticationService = authenticationService
}

func (state State) getCookieValue() string {
	return state.userSessionToken.tokenId
}

func (state State) getCurrentRealmPath() string {
	return getRealmPath(state.getRealm())
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

type HasTokenParam struct {
	TokenType string
}

func (state State) hasUserBearerToken() bool {
	return hasToken(
		HasTokenParam{
			TokenType: "userBearer",
		},
	)
}
func (state State) hasSaBearerToken() bool {
	return hasToken(
		HasTokenParam{
			TokenType: "saBearer",
		},
	)
}
func (state State) hasUserSessionToken() bool {
	return hasToken(
		HasTokenParam{
			TokenType: "userSession",
		},
	)
}

func (state State) getAdminClientRedirectUri() string {
	return constants.RedirectUrlTemplate
}

func hasToken(params HasTokenParam) bool {
	//todo
	return false
}
