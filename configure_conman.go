// Copyright 2019-2020 Hewlett Packard Enterprise Development LP

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	compcreds "stash.us.cray.com/HMS/hms-compcredentials"
	sstorage "stash.us.cray.com/HMS/hms-securestorage"
)

// Location of the configuration file
const conmanConf string = "/etc/conman.conf"

// Struct to hold hsm redfish endpoint information
type redfishEndpoint struct {
	ID       string
	Type     string
	FQDN     string
	User     string
	Password string
}

// Struct to hold hsm state component information
type stateComponent struct {
	ID    string
	Type  string
	Class string
}

// Helper function to execute an http command
func getURL(URL string) ([]byte, error) {
	var err error = nil
	log.Printf("URL: %s\n", URL)
	resp, err := http.Get(URL)
	if err != nil {
		// handle error
		log.Printf("Error on request to %s: %s", URL, err)
	}
	log.Printf("Response Status code: %d\n", resp.StatusCode)
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Printf("Error reading response: %s", err)
	}
	//fmt.Printf("Data: %s\n", data)
	return data, err
}

// Query hsm for redfish endpoint information
func getRedfishEndpoints() ([]redfishEndpoint, error) {
	log.Print("Gathering redfish endpoints from HSM")
	type response struct {
		RedfishEndpoints []redfishEndpoint
	}

	// RedfishEndpointURL
	URL := "http://cray-smd/hsm/v1/Inventory/RedfishEndpoints"
	data, err := getURL(URL)
	rp := response{}
	err = json.Unmarshal(data, &rp)
	if err != nil {
		log.Printf("Error unmarshalling data: %s", err)
		return nil, err
	}

	// log the initial redfish endpoints gathered
	for _, redEndpoint := range rp.RedfishEndpoints {
		log.Printf("  ID: %s, Type: %s, FQDN: %s", redEndpoint.ID, redEndpoint.Type, redEndpoint.FQDN)
	}

	return rp.RedfishEndpoints, nil
}

// Query hsm for state component information
func getStateComponents() ([]stateComponent, error) {
	log.Print("Gathering state components from HSM")
	// get the component states from hsm - includes river/mountain information
	type response struct {
		Components []stateComponent
	}

	// state components URL
	URL := "http://cray-smd/hsm/v1/State/Components"
	data, err := getURL(URL)
	rp := response{}
	err = json.Unmarshal(data, &rp)
	if err != nil {
		// handle error
		log.Panicf("Error unmarshalling data: %s", err)
	}

	// log the initial components
	for _, sc := range rp.Components {
		log.Printf("  ID: %s, Type: %s, Class: %s", sc.ID, sc.Type, sc.Class)
	}

	return rp.Components, nil
}

// Look up the creds for the input endpoints
func getPasswords(endpoints []redfishEndpoint) map[string]compcreds.CompCredentials {
	log.Print("Gathing creds from vault")
	// Get the passwords from Hashicorp Vault
	var xnames []string
	for _, endpoint := range endpoints {
		if endpoint.Type == "NodeBMC" {
			xnames = append(xnames, endpoint.ID)
		}
	}

	// Create the Vault adapter and connect to Vault
	ss, err := sstorage.NewVaultAdapter("secret")
	if err != nil {
		log.Panicf("Error: %#v\n", err)
	}

	// Initialize the CompCredStore struct with the Vault adapter.
	ccs := compcreds.NewCompCredStore("hms-creds", ss)

	// Read the credentails for a list of components from the CompCredStore
	// (backed by Vault).
	ccreds, err := ccs.GetCompCreds(xnames)
	if err != nil {
		log.Panicf("Error: %#v\n", err)
	}

	return ccreds
}

// Update the configuration file with the current river endpoints
func updateConfigFile() {
	log.Print("Updating the configuration file")

	// Get the BMC IP addresses and user, and password for individual nodes.
	// conman is only set up for River nodes.
	rfEndpoints, err := getRedfishEndpoints()
	if err != nil {
		log.Panicf("Error fetching redfish endpoints: %s", err)
	}

	// get the state information to find mountain/river designation
	stComps, err := getStateComponents()
	if err != nil {
		log.Panicf("Error fetching state components: %s", err)
	}

	// convert into a map of type per xname from state components information
	typeMap := make(map[string]string) // xname -> type[River/Mountain]
	for _, stComp := range stComps {
		if stComp.Type == "NodeBMC" {
			typeMap[stComp.ID] = stComp.Class
		}
	}

	// Create maps containing River and Mountain nodes
	riverNodes := make(map[string]redfishEndpoint) // xname -> redfish endpoint info
	mtnNodes := make(map[string]redfishEndpoint)   // xname -> redfish endpoint info
	for _, redEndpoint := range rfEndpoints {
		if tp, ok := typeMap[redEndpoint.ID]; ok {
			if tp == "River" {
				riverNodes[redEndpoint.ID] = redEndpoint
			} else if tp == "Mountain" {
				mtnNodes[redEndpoint.ID] = redEndpoint
			} else {
				log.Printf("Node not classified as river or mountain: %s", redEndpoint.ID)
			}
		}
	}

	// open the configuration file for output
	// TODO - start with base config and create new one so can be
	//  done more than once
	f, err := os.OpenFile(conmanConf, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		// log the problem and panic
		log.Panic(err)
	}
	defer f.Close()

	// collect the creds for the endpoints
	var passwords map[string]compcreds.CompCredentials
	passwords = getPasswords(rfEndpoints)

	// Add River endpoints to the config file to be accessed by ipmi
	for _, endpoint := range riverNodes {
		output := fmt.Sprintf("console name=\"%s\" dev=\"ipmi:%s\" ipmiopts=\"U:%s,P:%s,W:solpayloadsize\"\n",
			endpoint.ID,
			endpoint.FQDN,
			endpoint.User,
			passwords[endpoint.ID].Password)
		log.Print(output)
		if _, err = f.WriteString(output); err != nil {
			// log the error then panic
			// TODO - maybe a little harsh to kill the entire process here?
			log.Panic(err)
		}
	}
}

// Main loop for the application
func main() {
	// NOTE: this is a work in progress starting to restructure this application
	//  to manage the console state - watching for hardware changes and
	//  updating / restarting the conman process when needed

	log.Print("Starting conman_conf configuration")

	// Set up the conman configuration file.
	updateConfigFile()

}
