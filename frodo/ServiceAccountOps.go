package frodo

import (
	"fmt"
	"github.com/darkedges/go-frodo-lib/constants"
	"github.com/goccy/go-json"
)

func (frodo Frodo) ReadServiceAccount(serviceAccountId string) (ServiceAccountType, error) {
	frodo.DebugMessage("ServiceAccountOps.GetServiceAccount: start")
	serviceAccount, err := frodo.getManagedObject(GetManagedObjectParams{
		Type:   constants.MOType,
		Id:     serviceAccountId,
		Fields: []string{"*"},
	})
	if err != nil {
		return ServiceAccountType{}, err
	}
	frodo.DebugMessage(fmt.Sprintf("%+v", serviceAccount))
	frodo.DebugMessage("ServiceAccountOps.GetServiceAccount: end")
	return serviceAccount, nil
}

func (frodo Frodo) CreateServiceAccount(moData ServiceAccountType) (ServiceAccountType, error) {
	frodo.DebugMessage("ServiceAccountOps.CreateServiceAccount: start")

	jcart, _ := json.MarshalIndent(moData, "", "  ")
	frodo.DebugMessage(fmt.Sprintf("moData: %s", string(jcart)))
	serviceAccount, err := frodo.createManagedObject(constants.MOType, moData)
	if err != nil {
		return ServiceAccountType{}, err
	}
	frodo.DebugMessage(fmt.Sprintf("%+v", serviceAccount))
	frodo.DebugMessage("ServiceAccountOps.CreateServiceAccount: end")
	return serviceAccount, nil
}

func (frodo Frodo) UpdateServiceAccount(moData ServiceAccountType) (ServiceAccountType, error) {
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: start")
	id := moData.ID
	moData.Rev = ""
	moData.ID = ""
	moData.MaxIdleTime = ""
	moData.MaxSessionTime = ""
	moData.QuotaLimit = ""
	moData.MaxCachingTime = ""
	serviceAccount, err := frodo.putManagedObject(constants.MOType, id, moData, false)
	if err != nil {
		return ServiceAccountType{}, err
	}
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: end")
	return serviceAccount, nil
}

func (frodo Frodo) PatchServiceAccount(id string, operations []Operation) (ServiceAccountType, error) {
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: start")
	serviceAccount, err := frodo.patchManagedObject(constants.MOType, id, operations, "")
	if err != nil {
		return ServiceAccountType{}, err
	}
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: end")
	return serviceAccount, nil
}

func (frodo Frodo) DeleteServiceAccount(id string) (ServiceAccountType, error) {
	frodo.DebugMessage("ServiceAccountOps.DeleteServiceAccount: start")
	serviceAccount, err := frodo.deleteManagedObject(constants.MOType, id)
	if err != nil {
		return ServiceAccountType{}, err
	}
	frodo.DebugMessage("ServiceAccountOps.DeleteServiceAccount: end")
	return serviceAccount, nil
}
