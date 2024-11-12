package frodo

import (
	"testing"

	. "github.com/karlseguin/expect"
)

var host0 = "https://instance0/am"
var host1 = "https://instance1/am"
var host2 = "https://instance2/am"

func TestCreateInstanceWithAdminAccount(t *testing.T) {
	params1 := main.Params{}
	params1.Host = "https://instance1/am"
	params1.User = "admin1"
	params1.Pass = "password1"
	instance1, _ := main.CreateInstanceWithAdminAccount(params1)
	params2 := main.Params{}
	params2.Host = "https://instance2/am"
	params2.User = "admin2"
	params2.Pass = "password2"
	instance2, _ := main.CreateInstanceWithAdminAccount(params2)
	Expect(host1).To.Equal(host1)
	Expect(instance1.state().Host).To.Equal(host1)
	Expect(instance1.state().Username).To.Equal("admin1")
	Expect(instance1.state().Password).To.Equal("password1")
	Expect(instance2.state().Host).To.Equal(host2)
	Expect(instance2.state().Username).To.Equal("admin2")
	Expect(instance2.state().Password).To.Equal("password2")
}

//func TestGetTokens(t *testing.T) {
//	state := State{}
//	state.Host = "https://am.darkedges.com.au/openam"
//	state.Realm = "root"
//	state.Username = "amadmin"
//	state.Password = "Passw0rd"
//	result := GetTokens()
//	Expect(12).To.Equal(12)
//	Expect(result).To.Equal("")
//	// Expect(state.getDeploymentType()).toEqual('cloud');
//	// Expect(state.getCookieName()).toBeTruthy();
//	// Expect(state.getCookieValue()).toBeTruthy();
//	// Expect(state.getBearerToken()).toBeTruthy();
//	// Expect(state.getCookieName()).toMatchSnapshot();
//	// Expect(state.getCookieValue()).toMatchSnapshot();
//	// Expect(state.getBearerToken()).toMatchSnapshot();
//
//}
