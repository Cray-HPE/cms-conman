// Copyright 2019 Cray Inc. All Rights Reserved.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	compcreds "stash.us.cray.com/HMS/hms-common/pkg/compcredentials"
	sstorage "stash.us.cray.com/HMS/hms-common/pkg/securestorage"
)

const conmanConf string = "/etc/conman.conf"

type redfishEndpoint struct {
	ID       string
	Type     string
	FQDN     string
	User     string
	Password string
}

func getURL(URL string) ([]byte, error) {
	var err error = nil
	fmt.Printf("URL: %s\n", URL)
	resp, err := http.Get(URL)
	if err != nil {
		// handle error
		fmt.Printf("Error on request to %s: %s", URL, err)
	}
	fmt.Printf("Response Status code: %d\n", resp.StatusCode)
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		fmt.Printf("Error reading response: %s", err)
	}
	fmt.Printf("Data: %s\n", data)
	return data, err
}

// Get list of nodes from HSM
func getRedfishEndpoints() ([]redfishEndpoint, error) {
	// Description: Get the Redfish Endpoints, which are all BMCs.
	// Returns:
	//   A list containing BMC objects

	type response struct {
		RedfishEndpoints []redfishEndpoint
	}

	// RedfishEndpointURL
	URL := "http://cray-smd/hsm/v1/Inventory/RedfishEndpoints"
	data, err := getURL(URL)
	rp := response{}
	err = json.Unmarshal(data, &rp)
	if err != nil {
		// handle error
		fmt.Printf("Error unmarshalling data: %s", err)
		os.Exit(1)
	}

	return rp.RedfishEndpoints, nil

}

type componentEndpoint struct {
	ID   string
	Type string
}

// Get list of nodes from HSM
func getComponentEndpoints() ([]componentEndpoint, error) {
	// Description: Get the Redfish Endpoints, which are all BMCs.
	// Returns:
	//   A list containing BMC objects

	type response struct {
		componentEndpoints []componentEndpoint
	}

	// componentEndpointURL
	URL := "http://cray-smd/hsm/v1/Inventory/ComponentEndpoints"
	data, err := getURL(URL)
	rp := response{}
	err = json.Unmarshal(data, &rp)
	if err != nil {
		// handle error
		fmt.Printf("Error unmarshalling data: %s", err)
		os.Exit(1)
	}

	return rp.componentEndpoints, nil
}

func get_passwords(endpoints []redfishEndpoint) map[string]compcreds.CompCredentials {
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
		fmt.Printf("Error: %#v\n", err)
		panic(err)
	}

	// Initialize the CompCredStore struct with the Vault adapter.
	ccs := compcreds.NewCompCredStore("hms-creds", ss)

	// Read the credentails for a list of components from the CompCredStore
	// (backed by Vault).
	ccreds, err := ccs.GetCompCreds(xnames)
	if err != nil {
		fmt.Printf("Error: %#v\n", err)
		panic(err)
	}

	return ccreds
}

func main() {
	// Set up the conman configuration file.
	// Get the BMC IP addresses and user, and password for individual nodes.
	// conman is only set up for River nodes.
	var rfEndpoints []redfishEndpoint
	rfEndpoints, _ = getRedfishEndpoints()

	var compEndpoints []componentEndpoint
	compEndpoints, _ = getComponentEndpoints()

	// Weed out the Mountain nodes from the entire group of nodes
	// What remains will be River nodes

	// Create a map containing River and Mountain nodes
	allNodes := make(map[string]redfishEndpoint)
	for _, redEndpoint := range rfEndpoints {
		allNodes[redEndpoint.ID] = redEndpoint
	}

	// Remove the Mountain nodes from allNodes.
	for _, compEndpoint := range compEndpoints {
		// Strip off the bX characters from the Chassis BMC
		compEndpoint_prefix := compEndpoint.ID[:strings.Index(compEndpoint.ID, "b")]

		for node := range allNodes {
			// If the Chassis BMC matches the start of a node component,
			// then remove it from the list.  This will remove all Mountain
			// nodes
			if strings.HasPrefix(node, compEndpoint_prefix) {
				delete(allNodes, node)
			}
		}
	}

	f, err := os.OpenFile(conmanConf, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Loop through Redfish Endpoints; only operate on NodeBMCs
	var passwords map[string]compcreds.CompCredentials
	passwords = get_passwords(rfEndpoints)

	for _, endpoint := range allNodes {
		if endpoint.Type == "NodeBMC" {
			output := fmt.Sprintf("console name=\"%s\" dev=\"ipmi:%s\" ipmiopts=\"U:%s,P:%s,W:solpayloadsize\"\n",
				endpoint.ID,
				endpoint.FQDN,
				endpoint.User,
				passwords[endpoint.ID].Password)
			if _, err = f.WriteString(output); err != nil {
				panic(err)
			}
		}
	}
}
