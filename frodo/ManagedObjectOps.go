package frodo

import (
	"fmt"
	"github.com/darkedges/go-frodo-lib/constants"
	"github.com/goccy/go-json"
	"io"
	"net/http"
	"strings"
	"time"
)

type GetManagedObjectParams struct {
	Type   string
	Id     string
	Fields []string
}

type CreateManagedObjectParams struct {
	Type string
	Id   string
	Data any
}

type Operation struct {
	Operation string `json:"operation"`
	Field     string `json:"field"`
	Value     string `json:"value"`
}

func (frodo Frodo) getManagedObject(params GetManagedObjectParams) (ServiceAccountType, error) {
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
		return ServiceAccountType{}, err
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	var responseObject ServiceAccountType = ServiceAccountType{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

func (frodo Frodo) createManagedObject(moType string, moData any) (ServiceAccountType, error) {
	urlString := fmt.Sprintf(constants.CreateManagedObjectURLTemplate, frodo.getIdmBaseUrl(), moType)
	payload, _ := json.MarshalIndent(moData, "", "  ")
	data := frodo.generateIdmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		body:            string(payload),
		method:          "POST",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		return ServiceAccountType{}, err
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	frodo.DebugMessage(fmt.Sprintf("reponseData: %s", responseData))
	var responseObject ServiceAccountType = ServiceAccountType{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

func (frodo Frodo) putManagedObject(moType string, id string, moData any, failIfExists bool) (ServiceAccountType, error) {
	urlString := fmt.Sprintf(constants.ManagedObjectByIdURLTemplate, frodo.getIdmBaseUrl(), moType, id)
	payload, _ := json.MarshalIndent(moData, "", "  ")
	headers := http.Header{}
	if failIfExists {
		headers.Add("If-None-Match", "*")
	}
	data := frodo.generateIdmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		body:            string(payload),
		method:          "PUT",
		headers:         headers,
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		return ServiceAccountType{}, err
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	var responseObject = ServiceAccountType{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

func (frodo Frodo) patchManagedObject(moType string, id string, moData any, rev string) (ServiceAccountType, error) {
	urlString := fmt.Sprintf(constants.ManagedObjectByIdURLTemplate, frodo.getIdmBaseUrl(), moType, id)
	payload, _ := json.MarshalIndent(moData, "", "  ")
	headers := http.Header{}
	if rev != "" {
		headers.Add("If-Match", rev)
	}
	data := frodo.generateIdmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		body:            string(payload),
		method:          "PATCH",
		headers:         headers,
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		return ServiceAccountType{}, err
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	var responseObject = ServiceAccountType{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}

func (frodo Frodo) queryManagedObjects(moType string, filter string, fields []string, pageSize string, pageCookie string) []ServiceAccountType {
	//todo
	return []ServiceAccountType{}
}

func (frodo Frodo) queryAllManagedObjectsByType(moType string, fields []string, pageSize string, pageCookie string) []ServiceAccountType {
	//todo
	return []ServiceAccountType{}
}

func (frodo Frodo) deleteManagedObject(moType string, id string) (ServiceAccountType, error) {
	urlString := fmt.Sprintf(constants.ManagedObjectByIdURLTemplate, frodo.getIdmBaseUrl(), moType, id)
	data := frodo.generateIdmApi(HTTPRequestParams{
		resource:        map[string]string{},
		requestOverride: map[string]string{},
		url:             urlString,
		method:          "DELETE",
	})
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(&data)
	if err != nil {
		return ServiceAccountType{}, err
	}
	defer resp.Body.Close()
	responseData, err := io.ReadAll(resp.Body)
	var responseObject ServiceAccountType = ServiceAccountType{}
	err = json.Unmarshal(responseData, &responseObject)
	return responseObject, nil
}
