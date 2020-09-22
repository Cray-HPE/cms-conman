// Copyright 2019 Cray Inc. All Rights Reserved.

// There is very little (if any) logging in this file due to the sensitive nature of the purpose of this file.

package compcredentials

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	sstorage "stash.us.cray.com/HMS/hms-securestorage"
)

const DefaultCompCredPath = "hms-creds"

// Usage example using vault as the backing secure storage:
//import (
//    "log"
//    sstorage "stash.us.cray.com/HMS/hms-securestorage"
//    cc "stash.us.cray.com/HMS/hms-compcredentials"
//)
//func compCredVaultExample() {
//    // Create the Vault adapter and connect to Vault
//    ss, err := sstorage.NewVaultAdapter("secret")
//    if err != nil {
//        log.Printf("Error: %#v\n", err)
//        panic(err)
//    }
//
//    // Initialize the CompCredStore struct with the Vault adapter.
//    ccs := NewCompCredStore("hms-creds", ss)
//
//    // Create a new set of credentials for a component.
//    compCred := cc.CompCredentials{
//        Xname: "x0c0s21b0"
//        URL: "10.4.0.8/redfish/v1/UpdateService"
//        Username: "test"
//        Password: "123"
//    }
//
//    // Store the credentials in the CompCredStore (backed by Vault).
//    err = ccs.StoreCompCred(compCred)
//    if err != nil {
//        log.Printf("Error: %#v\n", err)
//        panic(err)
//    }
//
//    // Read the credentails for a component from the CompCredStore
//    // (backed by Vault).
//    var ccred CompCredentials
//    ccred, err = ccs.GetCompCred(compCred.Xname)
//    if err != nil {
//        log.Printf("Error: %#v\n", err)
//        panic(err)
//    }
//    log.Printf("%#v\n", ccred)
//
//    // Read the credentails for a list of components from the CompCredStore
//    // (backed by Vault).
//    credList := []string{compCred.Xname}
//    ccreds, err := ccs.GetCompCreds(credList)
//    if err != nil {
//        log.Printf("Error: %#v\n", err)
//        panic(err)
//    }
//    log.Printf("%#v\n", ccreds)
//
//    // Read the credentails for all components in the CompCredStore
//    // (backed by Vault).
//    allCreds, err := ccs.GetAllCompCreds()
//    if err != nil {
//        log.Printf("Error: %#v\n", err)
//        panic(err)
//    }
//    log.Printf("%#v\n", allCreds)
//}

type CompCredStore struct {
	CCPath string
	SS     sstorage.SecureStorage
}

// Create a new CompCredStore struct that uses a SecureStorage backing store.
func NewCompCredStore(keyPath string, ss sstorage.SecureStorage) *CompCredStore {
	ccs := &CompCredStore{
		CCPath: keyPath,
		SS:     ss,
	}
	return ccs
}

// Get the credentials for a component specified by xname from the secure store.
func (ccs *CompCredStore) GetCompCred(xname string) (CompCredentials, error) {
	var compCred CompCredentials

	err := ccs.SS.Lookup(ccs.CCPath+"/"+xname, &compCred)
	if err != nil {
		return compCred, err
	}

	return compCred, nil
}

// Get the credentials for all components in the secure store.
func (ccs *CompCredStore) GetAllCompCreds() (map[string]CompCredentials, error) {
	var compCreds map[string]CompCredentials

	keyList, err := ccs.SS.LookupKeys(ccs.CCPath)
	if err != nil {
		return compCreds, err
	}

	compCreds, err = ccs.GetCompCreds(keyList)
	if err != nil {
		return compCreds, err
	}

	return compCreds, nil
}

// Get the credentials for a list of components in the secure store.
func (ccs *CompCredStore) GetCompCreds(xnames []string) (map[string]CompCredentials, error) {

	compCreds := make(map[string]CompCredentials)

	for _, xname := range xnames {
		creds, err := ccs.GetCompCred(xname)
		if err != nil {
			log.WithField("xname", xname).Error("Unable to map value to CompCredentials")
			// Not sure if this is the best course of action, but for now we'll just take what we can get.
			continue
		}

		compCreds[creds.Xname] = creds
	}

	return compCreds, nil
}

// Store the credentials for a component in the secure store.
func (ccs *CompCredStore) StoreCompCred(compCred CompCredentials) error {
	err := ccs.SS.Store(ccs.CCPath+"/"+compCred.Xname, compCred)
	if err != nil {
		return err
	}

	return nil
}

type CompCredentials struct {
	Xname        string `json:"xname"`
	URL          string `json:"url"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	SNMPAuthPass string `json:"SNMPAuthPass,omitempty"`
	SNMPPrivPass string `json:"SNMPPrivPass,omitempty"`
}

// Due to the sensitive nature of the data in CompCredentials, make a custom String function
// to prevent passwords from being printed directly (accidentally) to output.
func (compCred CompCredentials) String() string {
	return fmt.Sprintf("URL: %s, Username: %s, Password: <REDACTED>, SNMP Passes: <REDACTED>/<REDACTED>",
		compCred.URL, compCred.Username)
}
