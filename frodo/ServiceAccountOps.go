package frodo

import (
	"fmt"
	"github.com/darkedges/go-frodo-lib/constants"
)

func (frodo Frodo) ReadServiceAccount(serviceAccountId string) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.GetServiceAccount: start")
	serviceAccount := frodo.getManagedObject(GetManagedObjectParams{
		Type:   constants.MOType,
		Id:     serviceAccountId,
		Fields: []string{"*"},
	})
	frodo.DebugMessage(fmt.Sprintf("%+v", serviceAccount))
	frodo.DebugMessage("ServiceAccountOps.GetServiceAccount: end")
	return serviceAccount
}

func (frodo Frodo) CreateServiceAccount(moData ServiceAccountType) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.CreateServiceAccount: start")
	serviceAccount := frodo.createManagedObject(constants.MOType, moData)
	frodo.DebugMessage(fmt.Sprintf("%+v", serviceAccount))
	frodo.DebugMessage("ServiceAccountOps.CreateServiceAccount: end")
	return serviceAccount
}

func (frodo Frodo) UpdateServiceAccount(moData ServiceAccountType) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: start")
	id := moData.ID
	moData.Rev = ""
	moData.ID = ""
	moData.MaxIdleTime = ""
	moData.MaxSessionTime = ""
	moData.QuotaLimit = ""
	moData.MaxCachingTime = ""
	serviceAccount := frodo.putManagedObject(constants.MOType, id, moData, false)
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: end")
	return serviceAccount
}

func (frodo Frodo) PatchServiceAccount(id string, operations []Operation) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: start")
	serviceAccount := frodo.patchManagedObject(constants.MOType, id, operations, "")
	frodo.DebugMessage("ServiceAccountOps.UpdateServiceAccount: end")
	return serviceAccount
}

func (frodo Frodo) DeleteServiceAccount(id string) ServiceAccountType {
	frodo.DebugMessage("ServiceAccountOps.DeleteServiceAccount: start")
	serviceAccount := frodo.deleteManagedObject(constants.MOType, id)
	frodo.DebugMessage("ServiceAccountOps.DeleteServiceAccount: end")
	return serviceAccount
}
