// Copyright 2019-2020 Hewlett Packard Enterprise Development LP

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	compcreds "stash.us.cray.com/HMS/hms-compcredentials"
	sstorage "stash.us.cray.com/HMS/hms-securestorage"
)

// Location of the configuration file
const baseConfFile string = "/app/conman_base.conf"
const confFile string = "/etc/conman.conf"

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

// read the begining of the input file to see if we should skip this update
func willUpdateConfig(fp *os.File) bool {
	// if the first line of the base configuration file has '# UDPATE_CONFIG=FALSE'
	// then bail on the update
	buff := make([]byte, 50)
	n, err := fp.Read(buff)
	if err != nil || n < 50 {
		log.Printf("Read of base configuration failed. Bytes read: %d, error:%s", n, err)
		return false
	}

	// convert to string for easier handling
	s := string(buff[:n])
	log.Printf("Skip update test line: %s", s)

	// search for config flag
	retVal := false
	ss := "UPDATE_CONFIG="
	pos := strings.Index(s, ss)
	if pos > 0 {
		// found it - get the value
		valPos := pos + len(ss)
		retVal = s[valPos] != 'F' && s[valPos] != 'f'
		log.Printf("Found update string. pos:%d, valPod:%d, val:%q, retVal:%t", pos, valPos, s[valPos], retVal)
	} else {
		log.Printf("Didn't find update string")
	}

	// reset the file pointer
	_, err = fp.Seek(0, 0)
	if err != nil {
		log.Printf("Reset of file pointer to begining of file failed:%s", err)
	}

	return retVal
}

// Update the configuration file with the current river endpoints
func updateConfigFile(forceUpdate bool) {
	log.Print("Updating the configuration file")

	// open the base file
	bf, err := os.Open(baseConfFile)
	if err != nil {
		// log the problem and bail
		log.Panicf("Unable to open base config file: %s", err)
	}
	defer bf.Close()

	// if the skip update flag has been set then don't do this update
	if !forceUpdate && !willUpdateConfig(bf) {
		log.Print("Skipping update due to base config file flag")
		return
	}

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
	cf, err := os.OpenFile(confFile, os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		// log the problem and panic
		log.Panicf("Unable to open config file to write: %s", err)
	}
	defer cf.Close()

	// copy the base file to the configuration file
	_, err = io.Copy(cf, bf)
	if err != nil {
		log.Printf("Unable to copy base file into config: %s", err)
	}

	// collect the creds for the endpoints
	var passwords map[string]compcreds.CompCredentials
	passwords = getPasswords(rfEndpoints)

	// Add River endpoints to the config file to be accessed by ipmi
	for _, endpoint := range riverNodes {
		// log the output line withtout the password present
		log.Printf("console name=\"%s\" dev=\"ipmi:%s\" ipmiopts=\"U:%s,P:REDACTED,W:solpayloadsize\"\n",
			endpoint.ID,
			endpoint.FQDN,
			endpoint.User)
		// write the line to the config file
		output := fmt.Sprintf("console name=\"%s\" dev=\"ipmi:%s\" ipmiopts=\"U:%s,P:%s,W:solpayloadsize\"\n",
			endpoint.ID,
			endpoint.FQDN,
			endpoint.User,
			passwords[endpoint.ID].Password)
		if _, err = cf.WriteString(output); err != nil {
			// log the error then panic
			// TODO - maybe a little harsh to kill the entire process here?
			log.Panic(err)
		}
	}
}

// Execute the conman process
func executeConman() {
	// This function  will start an instance of 'conmand' on the local
	// system, route the output from that process into this log stream,
	// and exit when that process is killed
	log.Print("Starting a new intance of conmand")

	// Start the conmand command with arguments
	cmd := exec.Command("conmand", "-F", "-v", "-c", confFile)

	// capture the stderr and stdout pipes from this command
	cmdStdErr, err := cmd.StderrPipe()
	if err != nil {
		log.Panicf("Unable to connect to conmand stderr pipe: %s", err)
	}
	cmdStdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Panicf("Unable to connect to conmand stdout pipe: %s", err)
	}

	// spin a thread to read the stderr pipe
	go func() {
		log.Print("Starting log of conmand stderr output")
		errReader := bufio.NewReader(cmdStdErr)
		for {
			// read the next line
			line, err := errReader.ReadString('\n')
			if err != nil {
				log.Print("Ending stderr logging from error:%s", err)
				break
			}
			log.Print(line)
		}
	}()

	// spin a thread to read the stdout pipe
	go func() {
		log.Print("Starting log of conmand stdout output")
		stdOutReader := bufio.NewReader(cmdStdOut)
		for {
			// read the next line
			line, err := stdOutReader.ReadString('\n')
			if err != nil {
				log.Print("Ending stdout logging from error:%s", err)
				break
			}
			log.Print(line)
		}
	}()

	// start the command
	log.Print("Starting conmand process")
	if err = cmd.Start(); err != nil {
		log.Panicf("Unable to start the command: %s", err)
	}

	// wait for the process to exit
	// NOTE - execution will stop here until the process completes!
	if err = cmd.Wait(); err != nil {
		log.Panicf("Error from command wait: %s", err)
	}
	log.Print("Conmand process has exited")
}

// Main loop for the application
func main() {
	// NOTE: this is a work in progress starting to restructure this application
	//  to manage the console state - watching for hardware changes and
	//  updating / restarting the conman process when needed

	// create a loop to execute the conmand command
	forceConfigUpdate := true
	for {
		// Set up or update the conman configuration file.
		// NOTE: do not let the user skip the update the first time through
		updateConfigFile(forceConfigUpdate)
		forceConfigUpdate = false

		// start the conmand process
		// NOTE: this function will not exit until the process exits, but
		//  spin up a new one on exit.  This will allow a user to manually
		//  kill the conmand process and this will restart while re-reading
		//  the configuration file.
		executeConman()
	}

}
