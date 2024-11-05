package constants

import (
	"strings"
)

const DEFAULT_REALM_KEY = "__default__realm__"
const CLASSIC_DEPLOYMENT_TYPE_KEY = "classic"
const CLOUD_DEPLOYMENT_TYPE_KEY = "cloud"
const FORGEOPS_DEPLOYMENT_TYPE_KEY = "forgeops"
const ServerInfoApiVersion = "resource=1.1"

var DEPLOYMENT_TYPES = []string{
	CLASSIC_DEPLOYMENT_TYPE_KEY,
	CLOUD_DEPLOYMENT_TYPE_KEY,
	FORGEOPS_DEPLOYMENT_TYPE_KEY,
}

var DEPLOYMENT_TYPE_REALM_MAP = map[string]string{
	CLASSIC_DEPLOYMENT_TYPE_KEY:  "/",
	CLOUD_DEPLOYMENT_TYPE_KEY:    "alpha",
	FORGEOPS_DEPLOYMENT_TYPE_KEY: "/",
}

const AuthenticateUrlTemplate = "%s/json%s/authenticate"

const AuthenticateWithServiceUrlTemplate = AuthenticateUrlTemplate + "?authIndexType=service&authIndexValue=%s"
const SessionInfoURLTemplate = "%s/json%s/sessions/?_action=getSessionInfo"
const ServerInfoUrlTemplate = "%s/json/serverinfo/%s"
const RedirectUrlTemplate = "/platform/appAuthHelperRedirect.html"
const AuthorizeUrlTemplate = "%s/oauth2%s/authorize"
const AccessTokenUrlTemplate = "%s/oauth2%s/access_token"
const ManagedObjectByIdURLTemplate = "%s/managed/%s/%s"
const EnvInfoURLTemplate = "%s/environment/info"

var s = struct {
	OpenIdScope                    string
	ProfileScope                   string
	AmFullScope                    string
	IdmFullScope                   string
	AutoAccessFullScope            string
	IGAFullScope                   string
	AnalyticsFullScope             string
	AMIntrospectRealmTokenScope    string
	AMIntrospectAllTokens          string
	AMIntrospectAllTokensAnyRealm  string
	CertificateFullScope           string
	CertificateReadScope           string
	ESVFullScope                   string
	ESVReadScope                   string
	ESVUpdateScope                 string
	ESVRestartScope                string
	ContentSecurityPolicyFullScope string
	FederationFullScope            string
	FederationReadScope            string
	ReleaseFullScope               string
	SSOCookieFullScope             string
	CustomDomainFullScope          string
	PromotionScope                 string
	WafFullScope                   string
	WafReadScope                   string
	WafWriteScope                  string
	CookieDomainsFullScope         string
	FederationEnforcementFullScope string
}{
	OpenIdScope:                    "openid",
	ProfileScope:                   "profile",
	AmFullScope:                    "fr:am:*",
	IdmFullScope:                   "fr:idm:*",
	AutoAccessFullScope:            "fr:autoaccess:*",
	IGAFullScope:                   "fr:iga:*",
	AnalyticsFullScope:             "fr:idc:analytics:*",
	AMIntrospectRealmTokenScope:    "am-introspect-all-tokens",
	AMIntrospectAllTokens:          "am-introspect-all-tokens",
	AMIntrospectAllTokensAnyRealm:  "am-introspect-all-tokens-any-realm",
	CertificateFullScope:           "fr:idc:certificate:*",
	CertificateReadScope:           "fr:idc:certificate:read",
	ESVFullScope:                   "fr:idc:esv:*",
	ESVReadScope:                   "fr:idc:esv:read",
	ESVUpdateScope:                 "fr:idc:esv:update",
	ESVRestartScope:                "fr:idc:esv:restart",
	ContentSecurityPolicyFullScope: "fr:idc:content-security-policy:*",
	FederationFullScope:            "fr:idc:federation:*",
	FederationReadScope:            "fr:idc:federation:read",
	ReleaseFullScope:               "fr:idc:release:*",
	SSOCookieFullScope:             "fr:idc:sso-cookie:*",
	CustomDomainFullScope:          "fr:idc:custom-domain:*",
	PromotionScope:                 "fr:idc:promotion:*",
	WafFullScope:                   "fr:idc:proxy-connect:*",
	WafReadScope:                   "fr:idc:proxy-connect:read",
	WafWriteScope:                  "fr:idc:proxy-connect:write",
	CookieDomainsFullScope:         "fr:idc:cookie-domain:*",
	FederationEnforcementFullScope: "fr:idc:federation:*",
}

var CLOUD_ADMIN_DEFAULT_SCOPES = []string{
	s.AnalyticsFullScope,
	s.AutoAccessFullScope,
	s.CertificateFullScope,
	s.ContentSecurityPolicyFullScope,
	s.CookieDomainsFullScope,
	s.CustomDomainFullScope,
	s.ESVFullScope,
	s.FederationEnforcementFullScope,
	s.IdmFullScope,
	s.IGAFullScope,
	s.OpenIdScope,
	s.PromotionScope,
	s.ReleaseFullScope,
	s.SSOCookieFullScope,
	s.WafFullScope,
}
var FORGEOPS_ADMIN_DEFAULT_SCOPES = []string{
	s.IdmFullScope,
	s.OpenIdScope,
}

var SERVICE_ACCOUNT_DEFAULT_SCOPES = []string{
	s.AmFullScope,
	s.AnalyticsFullScope,
	s.AutoAccessFullScope,
	s.CertificateFullScope,
	s.ContentSecurityPolicyFullScope,
	s.CookieDomainsFullScope,
	s.CustomDomainFullScope,
	s.ESVFullScope,
	s.IdmFullScope,
	s.IGAFullScope,
	s.PromotionScope,
	s.ReleaseFullScope,
	s.SSOCookieFullScope,
	s.WafFullScope,
}
var CloudAdminScopes = strings.Join(CLOUD_ADMIN_DEFAULT_SCOPES, " ")
var ForgeopsAdminScopes = strings.Join(FORGEOPS_ADMIN_DEFAULT_SCOPES, " ")
var ServiceAccountDefaultScopes = strings.Join(SERVICE_ACCOUNT_DEFAULT_SCOPES, " ")

var MOType = "svcacct"
