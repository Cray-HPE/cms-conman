// Copyright 2019-2021 Hewlett Packard Enterprise Development LP

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hpcloud/tail"
	"github.com/tidwall/gjson"
	compcreds "stash.us.cray.com/HMS/hms-compcredentials"
	sstorage "stash.us.cray.com/HMS/hms-securestorage"
)

// Location of the configuration file
const baseConfFile string = "/app/conman_base.conf"
const confFile string = "/etc/conman.conf"
const logRotDir string = "/var/log/conman.old"
const conAggLogFile string = "/var/log/conman/consoleAgg.log"
const logRotConfFile string = "/etc/logrotate.d/conman"
const logRotStateFile string = "/var/log/rot_conman.state"

// Location of the Mountain BMC console ssh key pair files.
// These are obtained or generated when the pod is created.
const mountainConsoleKey string = "/etc/conman.key"
const mountainConsoleKeyPub string = "/etc/conman.key.pub"

// Location of the Kubernetes service account token used to authenticate
// to Vault.  This is part of the pod deployment.
const svcAcctTokenFile string = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// The Vault base URI
const vaultBase = "http://cray-vault.vault:8200/v1"

// The Vault specific secret name of the Conman Mountain BMC console private key.
// If this secret does not exist Vault will be asked to create it.
const vaultBmcKeyName = "mountain-bmc-console"

// The Vault key type used when generating a new key intented for use with
// Mountian console ssh.
const vaultBmcKeyAlg = "rsa-2048"

// Global vars
var conAggMutex = &sync.Mutex{}
var conAggLogger *log.Logger = nil

// Struct to hold hsm redfish endpoint information
type redfishEndpoint struct {
	ID       string
	Type     string
	FQDN     string
	User     string
	Password string
}

// Provide a function to convert struct to string
func (re redfishEndpoint) String() string {
	return fmt.Sprintf("ID:%s, Type:%s, FQDN:%s, User:%s, Password:REDACTED", re.ID, re.Type, re.FQDN, re.User)
}

// Struct to hold hsm state component information
type stateComponent struct {
	ID    string
	Type  string
	Class string `json:",omitempty"`
	NID   int    `json:",omitempty"` // NOTE: NID value only valid if Role="Compute"
	Role  string `json:",omitempty"`
}

// Provide a function to convert struct to string
func (sc stateComponent) String() string {
	return fmt.Sprintf("ID:%s, Type:%s, Class:%s, NID:%d, Role:%s", sc.ID, sc.Type, sc.Class, sc.NID, sc.Role)
}

// Struct to hold all node level information needed to form a console connection
type nodeConsoleInfo struct {
	NodeName string // node xname
	BmcName  string // bmc xname
	BmcFqdn  string // full name of bmc
	Class    string // river/mtn class
	NID      int    // NID of the node
	Role     string // role of the node
}

// Provide a function to convert struct to string
func (nc nodeConsoleInfo) String() string {
	return fmt.Sprintf("NodeName:%s, BmcName:%s, BmcFqdn:%s, Class:%s, NID:%d, Role:%s",
		nc.NodeName, nc.BmcName, nc.BmcFqdn, nc.Class, nc.NID, nc.Role)
}

// Struct to hold the individual scsd node status
type scsdNode struct {
	Xname      string `json:"Xname"`
	StatusCode int    `json:"StatusCode"`
	StatusMsg  string `json:"StatusMsg"`
}

// Struct to hold the overall scsd reposnse
type scsdList struct {
	Targets []scsdNode `json:"Targets"`
}

// Helper function to execute an http command
func getURL(URL string, requestHeaders map[string]string) ([]byte, int, error) {
	var err error = nil
	log.Printf("getURL URL: %s\n", URL)
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		// handle error
		log.Printf("getURL Error creating new request to %s: %s", URL, err)
		return nil, -1, err
	}
	if requestHeaders != nil {
		for k, v := range requestHeaders {
			req.Header.Add(k, v)
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		// handle error
		log.Printf("getURL Error on request to %s: %s", URL, err)
		return nil, -1, err
	}
	log.Printf("getURL Response Status code: %d\n", resp.StatusCode)
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Printf("Error reading response: %s", err)
		return nil, resp.StatusCode, err
	}
	// NOTE: Dumping entire response clogs up the log file but keep for debugging
	//fmt.Printf("Data: %s\n", data)
	return data, resp.StatusCode, err
}

// Helper function to execute an http POST command
func postURL(URL string, requestBody []byte, requestHeaders map[string]string) ([]byte, int, error) {
	var err error = nil
	log.Printf("postURL URL: %s\n", URL)
	req, err := http.NewRequest("POST", URL, bytes.NewReader(requestBody))
	if err != nil {
		// handle error
		log.Printf("postURL Error creating new request to %s: %s", URL, err)
		return nil, -1, err
	}
	req.Header.Add("Content-Type", "application/json")
	if requestHeaders != nil {
		for k, v := range requestHeaders {
			req.Header.Add(k, v)
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		// handle error
		log.Printf("postURL Error on request to %s: %s", URL, err)
		return nil, -1, err
	}

	log.Printf("postURL Response Status code: %d\n", resp.StatusCode)
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Printf("postURL Error reading response: %s", err)
		return nil, resp.StatusCode, err
	}
	//fmt.Printf("Data: %s\n", data)
	return data, resp.StatusCode, err
}

// Query hsm for redfish endpoint information
func getRedfishEndpoints() ([]redfishEndpoint, error) {
	// if running in debug mode, skip hsm query
	if debugOnly {
		log.Print("DEBUGONLY mode - skipping redfish endpoints query")
		return nil, nil
	}

	log.Print("Gathering redfish endpoints from HSM")
	type response struct {
		RedfishEndpoints []redfishEndpoint
	}

	// Query hsm to get the redfish endpoints
	URL := "http://cray-smd/hsm/v1/Inventory/RedfishEndpoints"
	data, _, err := getURL(URL, nil)
	if err != nil {
		log.Printf("Unable to get redfish endpoints from hsm:%s", err)
		return nil, err
	}

	// decode the response
	rp := response{}
	err = json.Unmarshal(data, &rp)
	if err != nil {
		log.Printf("Error unmarshalling data: %s", err)
		return nil, err
	}

	// log the initial redfish endpoints gathered
	for _, redEndpoint := range rp.RedfishEndpoints {
		log.Printf("  %s", redEndpoint)
	}

	return rp.RedfishEndpoints, nil
}

// Query hsm for state component information
func getStateComponents() ([]stateComponent, error) {
	// if running in debug mode, skip hsm query
	if debugOnly {
		log.Print("DEBUGONLY mode - skipping state components query")
		return nil, nil
	}

	log.Print("Gathering state components from HSM")
	// get the component states from hsm - includes river/mountain information
	type response struct {
		Components []stateComponent
	}

	// get the state components from hsm
	URL := "http://cray-smd/hsm/v1/State/Components"
	data, _, err := getURL(URL, nil)
	if err != nil {
		log.Printf("Unable to get state component information from hsm:%s", err)
		return nil, err
	}

	// decode the response
	rp := response{}
	err = json.Unmarshal(data, &rp)
	if err != nil {
		// handle error
		log.Panicf("Error unmarshalling data: %s", err)
	}

	// log the initial components
	for _, sc := range rp.Components {
		log.Printf("  %s", sc)
	}

	return rp.Components, nil
}

// Look up the creds for the input endpoints
func getPasswords(bmcXNames []string) map[string]compcreds.CompCredentials {
	// if running in debug mode, skip hsm query
	if debugOnly {
		log.Print("DEBUGONLY mode - skipping creds query")
		return nil
	}

	// Get the passwords from Hashicorp Vault
	log.Print("Gathing creds from vault")

	// Create the Vault adapter and connect to Vault
	ss, err := sstorage.NewVaultAdapter("secret")
	if err != nil {
		log.Panicf("Error: %#v\n", err)
	}

	// Initialize the CompCredStore struct with the Vault adapter.
	ccs := compcreds.NewCompCredStore("hms-creds", ss)

	// Read the credentails for a list of components from the CompCredStore
	// (backed by Vault).
	ccreds, err := ccs.GetCompCreds(bmcXNames)
	if err != nil {
		log.Panicf("Error: %#v\n", err)
	}

	return ccreds
}

// read the begining of the input file to see if we should skip this update
func willUpdateConfig(fp *os.File) bool {
	// if the first line of the base configuration file has '# UPDATE_CONFIG=FALSE'
	// then bail on the update
	// NOTE: only reading first 50 bytes of file, should be at least that many
	//  present if this is a valid base configuration file and don't need to read more.
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

	// reset the file pointer so later read starts at begining of file
	_, err = fp.Seek(0, 0)
	if err != nil {
		log.Printf("Reset of file pointer to begining of file failed:%s", err)
	}

	return retVal
}

// Update the configuration file with the current river endpoints
func updateConfigFile(forceUpdate bool) (rvrNodes, mtnNodes []string, nodes []nodeConsoleInfo) {
	log.Print("Updating the configuration file")
	rvrNodes = nil
	mtnNodes = nil

	// open the base file
	log.Printf("Opening base configuration file: %s", baseConfFile)
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
		log.Printf("Unable to build configuration file - error fetching redfish endpoints: %s", err)
		return nil, nil, nil
	}

	// get the state information to find mountain/river designation
	stComps, err := getStateComponents()
	if err != nil {
		log.Printf("Unable to build configuration file - error fetching state components: %s", err)
		return nil, nil, nil
	}

	// create a lookup map for the redfish information
	rfMap := make(map[string]redfishEndpoint)
	for _, rf := range rfEndpoints {
		rfMap[rf.ID] = rf
	}

	// create river and mountain node information
	nodes = nil
	var xnames []string = nil
	for _, sc := range stComps {
		if sc.Type == "Node" {
			// create a new entry for this node - take initial vals from state component info
			newNode := nodeConsoleInfo{NodeName: sc.ID, Class: sc.Class, NID: sc.NID, Role: sc.Role}

			// pull information about the node BMC from the redfish information
			bmcName := sc.ID[0:strings.LastIndex(sc.ID, "n")]
			log.Printf("Parsing node info. Node:%s, bmc:%s", sc.ID, bmcName)
			if rf, ok := rfMap[bmcName]; ok {
				log.Print("  Found redfish endpoint info")
				// found the bmc in the redfish information
				newNode.BmcName = bmcName
				newNode.BmcFqdn = rf.FQDN

				// add to the list of nodes
				nodes = append(nodes, newNode)

				// add to list of bmcs to get creds from
				log.Printf("Added node: %s", newNode)
				xnames = append(xnames, bmcName)
			} else {
				log.Printf("Node with no BMC present: %s, bmcName:%s", sc.ID, bmcName)
			}
		}
	}

	// open the configuration file for output
	log.Printf("Opening conman configuration file for output: %s", confFile)
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
	passwords = getPasswords(xnames)

	// Add River endpoints to the config file to be accessed by ipmi
	for _, nodeCi := range nodes {
		// different types of connections for river and mountain nodes
		var output string
		if nodeCi.Class == "River" {
			// connect using ipmi
			creds := passwords[nodeCi.BmcName]
			log.Printf("console name=\"%s\" dev=\"ipmi:%s\" ipmiopts=\"U:%s,P:REDACTED,W:solpayloadsize\"\n",
				nodeCi.NodeName,
				nodeCi.BmcFqdn,
				creds.Username)
			// write the line to the config file
			output = fmt.Sprintf("console name=\"%s\" dev=\"ipmi:%s\" ipmiopts=\"U:%s,P:%s,W:solpayloadsize\"\n",
				nodeCi.NodeName,
				nodeCi.BmcFqdn,
				creds.Username,
				creds.Password)

			// record this as an active river node console
			rvrNodes = append(rvrNodes, nodeCi.NodeName)
		} else if nodeCi.Class == "Mountain" {
			log.Printf("console name=\"%s\" dev=\"/usr/bin/ssh-console %s\"\n",
				nodeCi.NodeName,
				nodeCi.NodeName)
			// write the line to the config file
			output = fmt.Sprintf("console name=\"%s\" dev=\"/usr/bin/ssh-console %s\"\n",
				nodeCi.NodeName,
				nodeCi.NodeName)
			mtnNodes = append(mtnNodes, nodeCi.NodeName)
		}

		// write the output line if there is anything present
		if len(output) > 0 {
			if _, err = cf.WriteString(output); err != nil {
				// log the error then panic
				// TODO - maybe a little harsh to kill the entire process here?
				log.Panic(err)
			}
		}

	}

	return rvrNodes, mtnNodes, nodes
}

// Watch the input file and append any new content to the aggregate console log file
func watchConsoleLogFile(xname string) {
	// TODO:
	// - test this keeps following files - the tail package is supposed to but
	//   need to verify

	// NOTE - v1 is just create a thread per file, add new when new hardware found,
	//  but don't stop when the hardware goes away.  Shouldn't hurt anything to watch
	//  a non-changing file...

	// if the aggregate logger is not set up, bail
	if conAggLogger == nil {
		log.Printf("Aggregate logger not present, unable to accumulate log of: %s", xname)
	}

	// follow the log file
	conf := tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true, // NOTE: it looks like file events don't work - poll instead
		Logger:    tail.DiscardingLogger,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2}, // set to open at the current end of file
	}

	// full path to the file
	filename := fmt.Sprintf("/var/log/conman/console.%s", xname)
	log.Printf("Starting to parse file: %s", filename)

	// start the tail operation
	tf, err := tail.TailFile(filename, conf)
	if err != nil {
		log.Printf("Failed to tail file %s with error:%s", filename, err)
		return
	}

	// parse the output of the tracked file
	// NOTE: this will read the file from that start position, then keep
	//  reading as the file is updated - this read should not end
	for line := range tf.Lines {
		// log the line
		writeToAggLog(fmt.Sprintf("console.hostname: %s %s", xname, line.Text))
	}
}

// function to manage writes to the aggragation log
func writeToAggLog(str string) {
	conAggMutex.Lock()
	defer conAggMutex.Unlock()
	if conAggLogger != nil {
		conAggLogger.Printf("%s", str)
	}
}

// Function to close/open a new aggregation logger
func respinAggLog() {
	// when the file changes due to log rotation we must recreate the logger
	conAggMutex.Lock()
	defer conAggMutex.Unlock()
	log.Printf("Respinning aggregation log")
	calf, err := os.OpenFile(conAggLogFile, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Printf("Could not open console aggregate log file: %s", err)
	} else {
		log.Printf("Restarted aggregation log file")
		conAggLogger = log.New(calf, "", 0)
		conAggLogger.Print("Starting aggregation log")
	}
}

// Take the output of the pipe and log it
func logPipeOutput(readPipe *io.ReadCloser, desc string) {
	log.Printf("Starting log of conmand %s output", desc)
	er := bufio.NewReader(*readPipe)
	for {
		// read the next line
		line, err := er.ReadString('\n')
		if err != nil {
			log.Printf("Ending %s logging from error:%s", desc, err)
			break
		}
		log.Print(line)
	}
}

// Execute the conman process
func executeConman() {
	// This function  will start an instance of 'conmand' on the local
	// system, route the output from that process into this log stream,
	// and exit when that process is killed
	log.Print("Starting a new instance of conmand")

	// NOTE - should not happen, just checking
	if command != nil {
		log.Print("ERROR: command not nil on entry to executeComman!!")
	}

	// Start the conmand command with arguments
	command = exec.Command("conmand", "-F", "-v", "-c", confFile)

	// capture the stderr and stdout pipes from this command
	cmdStdErr, err := command.StderrPipe()
	if err != nil {
		log.Panicf("Unable to connect to conmand stderr pipe: %s", err)
	}
	cmdStdOut, err := command.StdoutPipe()
	if err != nil {
		log.Panicf("Unable to connect to conmand stdout pipe: %s", err)
	}

	// spin a thread to read the stderr pipe
	go logPipeOutput(&cmdStdErr, "stderr")

	// spin a thread to read the stdout pipe
	go logPipeOutput(&cmdStdOut, "stdout")

	// start the command
	log.Print("Starting conmand process")
	if err = command.Start(); err != nil {
		log.Panicf("Unable to start the command: %s", err)
	}

	// wait for the process to exit
	// NOTE - execution will stop here until the process completes!
	if err = command.Wait(); err != nil {
		// Report error and pause before trying again
		log.Printf("Error from command wait: %s", err)
		time.Sleep(15 * time.Second)
	}
	command = nil
	log.Print("Conmand process has exited")
}

// Function to sent SIGHUP to running conmand process
func signalConman() {
	// send interupt to tell conman to re-initialize
	if command != nil {
		log.Print("Signaling conman with SIGHUP")
		command.Process.Signal(syscall.SIGHUP)
	} else {
		log.Print("Warning: Attempting to signal conman process when nil.")
	}
}

// Function to scan the process table for zombie processes
func watchForZombies() {
	for {
		// get the process information from the system
		zombies := findZombies()
		// look for zombies and terminate them
		for _, zombie := range zombies {
			// kill each zombie in a separate thread
			go killZombie(zombie)
		}
		// wait for a bit before looking again
		time.Sleep(30 * time.Second)
	}
}

// Find all the current zombie processes
func findZombies() []int {
	var zombies []int = nil
	var outBuf bytes.Buffer
	// Use a 'ps -eo' style command as the basis to search for zombie processes
	// and put the output in outBuf.
	cmd := exec.Command("ps", "-eo", "pid,stat")
	cmd.Stderr = &outBuf
	cmd.Stdout = &outBuf
	err := cmd.Run()
	if err != nil {
		log.Printf("Error getting current processes: %s", err)
	}
	// process the output buffer to find zombies
	var readLine string
	for {
		// pull off a line of output and
		if readLine, err = outBuf.ReadString('\n'); err == io.EOF {
			break
		} else if err != nil {
			log.Printf("Error reading current process output: %s", err)
			break
		}
		// NOTE: a 'STATUS' of "Z" denotes a zombie process
		cols := strings.Fields(readLine)
		if len(cols) >= 2 && cols[1] == "Z" {
			// found a zombie
			zPid, err := strconv.Atoi(cols[0])
			if err == nil {
				log.Printf("Found a zombie process: %d", zPid)
				zombies = append(zombies, zPid)
			} else {
				// atoi did not like our process "number"
				log.Printf("Thought we had a zombie, couldn't get pid:%s", readLine)
			}
		}
	}
	return zombies
}

// Kill (wait for) the zombie process with the given pid
func killZombie(pid int) {
	log.Printf("Killing zombie process: %d", pid)
	p, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("Error attaching to zombie process %d, err:%s", pid, err)
		return
	}
	// should just need to get the exit state to clean up process
	_, err = p.Wait()
	if err != nil {
		log.Printf("Error waiting for zombie process %d, err:%s", pid, err)
		return
	}
	log.Printf("Cleaned up zombie process: %d", pid)
}

// Ask Vault to generate a private key.  This method is called when it is necessary
// to have Vault create the key when it is missing or to enable future support
// for key rotation.  When a future REST api is added to supoort Conman operations
// this method should provide the backing support for key rotation.
func vaultGeneratePrivateKey(vaultToken string) (response []byte, responseCode int, err error) {
	// Create the parameters
	vaultParam := map[string]string{
		"type":       vaultBmcKeyAlg,
		"exportable": "true",
	}
	jsonVaultParam, err := json.Marshal(vaultParam)
	log.Printf("Preparing to ask Vault to generate the key with the parameters:\n %s",
		string(jsonVaultParam))
	if err != nil {
		return response, responseCode, err
	}

	// Tell vault to create the private key
	URL := vaultBase + "/transit/keys/" + vaultBmcKeyName
	vaultRequestHeaders := make(map[string]string)
	vaultRequestHeaders["X-Vault-Token"] = vaultToken
	response, responseCode, err = postURL(URL, jsonVaultParam, vaultRequestHeaders)

	// Return any general error.
	if err != nil {
		return response, responseCode, err
	}

	if responseCode != 204 {
		// Return an error for any unhandled http reposponse code.
		log.Printf(
			"Unexpected response from Vault when generating the key: %s  Http repsonse code: %d",
			response, responseCode)
		return response, responseCode, fmt.Errorf(
			"Unexpected response from Vault when generating the key: %s  Http repsonse code: %d",
			response, responseCode)
	}

	log.Printf("A new seceret for %s was generated in vault.", vaultBmcKeyName)
	return response, responseCode, nil
}

// Ask vault for the private key
func vaultExportPrivateKey(vaultToken string) (pvtKey string, response []byte, responseCode int, err error) {
	URL := vaultBase + "/transit/export/signing-key/" + vaultBmcKeyName
	vaultRequestHeaders := make(map[string]string)
	vaultRequestHeaders["X-Vault-Token"] = vaultToken
	response, responseCode, err = getURL(URL, vaultRequestHeaders)
	// Handle any general error with the request.
	if err != nil {
		log.Printf(
			"Unable to get the %s secret from vault: %s  Error was: %s",
			vaultBmcKeyName, vaultBase, err)
		return "", response, responseCode, fmt.Errorf("Unable to get the %s secret from vault: %s  Error was: %s",
			vaultBmcKeyName, vaultBase, err)
	}

	if responseCode == 404 {
		log.Printf("The vault secret %s was not found. It will need to be created.", vaultBmcKeyName)

		return "", response, 404, nil
	} else if responseCode == 200 {
		// Return the secret we found
		jsonElem := "data.keys.1" // See https://github.com/tidwall/gjson#path-syntax
		pvtKey := gjson.Get(string(response), jsonElem)
		if len(pvtKey.String()) == 0 {
			log.Printf(
				"Empty or missing %s element in Vault response",
				jsonElem)
			return "", response, responseCode, fmt.Errorf("Empty or missing %s element in Vault response",
				jsonElem)
		}
		return pvtKey.String(), response, 200, nil
	} else {
		// Return an error for any unhandled http reposponse code.
		log.Printf(
			"Unexpected response from Vault: %s  Http repsonse code: %d",
			response, responseCode)
		return "", response, responseCode, fmt.Errorf("Unexpected response from Vault: %s  Http repsonse code: %d",
			response, responseCode)
	}
}

// Obtain the private key from Vault.  The private key (aka Vault secret) is the
// only piece of the key pair which is stored in Vault.  The public key piece is
// created from the private via the standard ssh-keygen utility.
// If the private key can not be found then vault will be asked to generate and
// reuturn the new key.
func vaultGetPrivateKey(vaultToken string) (pvtKey string, err error) {
	// Ask vault for the existing key
	pvtKey, response, responseCode, err := vaultExportPrivateKey(vaultToken)
	if err != nil {
		return "", err
	}

	if responseCode == 200 {
		// Return the private key that was found in vault.
		return pvtKey, nil
	} else if responseCode == 404 {
		// Ask vault to generate a private key.
		response, responseCode, err := vaultGeneratePrivateKey(vaultToken)
		if err != nil {
			return "", err
		}

		// Handle any unexpected http error when generating the key.
		if responseCode != 200 {
			return "", fmt.Errorf(
				"Unexpected response from Vault when generating the key: %s  Http repsonse code: %d",
				response, responseCode)
		}

		// Ask vault again to export the newly generated private key.
		pvtKey, response, responseCode, err = vaultExportPrivateKey(vaultToken)
		if err != nil {
			return "", err
		}
		if responseCode != 200 {
			return "", fmt.Errorf(
				"Unexpected response from Vault when requesting the key: %s  Http repsonse code: %d",
				response, responseCode)
		}

		// Return the private key that was found in vault.
		return pvtKey, nil

	} else {
		// Handle an unexpected http response when initially requesting the key.
		return "", fmt.Errorf(
			"Unexpected response from Vault when requesting the key: %s  Http repsonse code: %d",
			response, responseCode)
	}
}

// Obtain Mountain node BMC credentials from Vault and stage them to the
// local file syetem.  A specific error will be returned in the event of
// any issues.
func vaultGetMountainConsoleCredentials() error {
	// Generate an ssh key pair (/etc/conman.key and /etc/conman.key.pub)
	// This will overwrite the existing public or private key files.

	// Authenticate to Vault
	svcAcctToken, err := ioutil.ReadFile(svcAcctTokenFile)
	if err != nil {
		log.Printf("Unable to read the service account token file: %s  Can not authenticate to vault.", err)
		return fmt.Errorf("Unable to read the service account token file: %s can not authenticate to vault", err)
	}

	vaultAuthParam := map[string]string{
		"jwt":  string(svcAcctToken),
		"role": "ssh-user-certs-compute"}
	jsonVaultAuthParam, _ := json.Marshal(vaultAuthParam)
	URL := vaultBase + "/auth/kubernetes/login"
	log.Printf("Attempting to authenticate to Vault at: %s", URL)
	response, responseCode, err := postURL(URL, jsonVaultAuthParam, nil)
	if err != nil {
		log.Printf("Unable to authenticate to Vault: %s", err)
		return fmt.Errorf("Unable to authenticate to Vault: %s", err)
	}
	// If the response code is not 200 then we failed authenticaton.
	if responseCode != 200 {
		log.Printf(
			"Vault authentication failed.  Response code: %d  Message: %s",
			responseCode, string(response))
		return fmt.Errorf(
			"Vault authentication failed.  Response code: %d  Message: %s",
			responseCode, string(response))
	}
	log.Printf("Vault authentication was successful.  Attempting to get BMC console key from vault")
	vaultToken := gjson.Get(string(response), "auth.client_token")

	// Get the private key from Vault.
	pvtKey, err := vaultGetPrivateKey(vaultToken.String())
	if err != nil {
		return err
	}
	log.Printf("Obtained BMC console key from vault.")

	// Write the private key to the local file system.
	err = ioutil.WriteFile(mountainConsoleKey, []byte(pvtKey), 0600)
	if err != nil {
		log.Printf("Failed to wtite our the private ssh key received from Vault.")
		return err
	}

	// Extract the public key from the private and convert to ssh format.
	log.Printf("Atempting to obtain BMC public console key.")
	var outBuf bytes.Buffer
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ssh-keygen -yf %s > %s",
		mountainConsoleKey, mountainConsoleKeyPub))
	cmd.Stderr = &outBuf
	cmd.Stdout = &outBuf
	err = cmd.Run()
	if err != nil {
		log.Printf("Error extracting the public key: %s", err)
		return err
	}
	log.Printf("Successfully obtained BMC public console key.")
	return nil // no error
}

// Used to generate Mountain console credentials in the event
// they can not be provided by Vault.
func generateMountainConsoleCredentials() error {
	// Generate an ssh key pair (/etc/conman.key and /etc/conman.key.pub)
	// This will overwrite the existing public or private key files.
	var outBuf bytes.Buffer
	//cmd := exec.Command("/usr/bin/ssh-keygen", "-qf", mountainConsoleKey, "-N", "''", "<<<y")
	// Error code 1 ...  TBD debug this further and eliminate the script if possible.
	cmd := exec.Command("/app/console-ssh-keygen")
	cmd.Stderr = &outBuf
	cmd.Stdout = &outBuf
	err := cmd.Run()
	if err != nil {
		log.Printf("Error generating console key pair: %s", err)
		return fmt.Errorf("Error generating console key pair: %s", err)
	}
	return nil
}

// Ensure that Mountain node console credentials are properly deployed.
func ensureMountainConsoleKeysDeployed(nodes []nodeConsoleInfo) {
	// Ensure that we have a console ssh key pair.  If the key pair
	// is not on the local file system then obtain it from Vault.  If
	// Vault is not available or we are otherwise unable to obtain the key
	// pair then generate it and log a message.  We want to minimize any
	// loss of console logs or console access due to a missing ssh
	// key pair.

	// if running in debug mode there won't be any nodes or vault present
	if debugOnly {
		log.Print("Running in debug mode - skipping mountain cred generation")
		return
	}

	// Check that we have key pair files on local storage
	_, errKey := os.Stat(mountainConsoleKey)
	_, errPub := os.Stat(mountainConsoleKeyPub)
	if os.IsNotExist(errKey) || os.IsNotExist(errPub) {
		// does not exist
		log.Printf("Obtaining Mountain console credentials from Vault")
		if err := vaultGetMountainConsoleCredentials(); err != nil {
			log.Printf("%s", err)
			log.Printf("Generating Mountain console credentials.")
			if err := generateMountainConsoleCredentials(); err != nil {
				log.Printf("Unable to generate credentials.  Error was: %s", err)
				return
			}
		}
	}

	// Read in the public key.
	pubKey, err := ioutil.ReadFile(mountainConsoleKeyPub)
	if err != nil {
		log.Printf("Unable to read the public key file: %s", err)
		return
	}

	// Obtain the list of Mountain bmcs from the node list.
	// Note there are two nodes per bmc and one update per bmc
	// is all that is required to set the ssh console key for
	// both nodes.
	mtnBmcList := make(map[string]string)
	for _, nodeCi := range nodes {
		if nodeCi.Class == "Mountain" {
			// log.Printf("Found BMC: %s %s", nodeCi.BmcName, nodeCi.BmcFqdn)
			mtnBmcList[nodeCi.BmcFqdn] = nodeCi.BmcName
		}
	}
	mtnNodeBmcArray := make([]string, 0, len(mtnBmcList))
	for bmcName := range mtnBmcList {
		mtnNodeBmcArray = append(mtnNodeBmcArray, bmcName)
	}

	// Create an HMS scsd json structure containing the Mountain BMC list and
	// the public key to deploy.
	scsdParam := map[string]interface{}{
		"Targets": mtnNodeBmcArray,
		"Params": map[string]string{
			"SSHConsoleKey": string(pubKey),
		},
		"Force": false,
	}
	jsonScsdParam, _ := json.Marshal(scsdParam)
	log.Printf("Preparing to call scsd with the parameters:\n %s", string(jsonScsdParam))

	// Call the HMS scsd service to deploy the public key.
	log.Print("Calling scsd to deploy Mountain BMC ssh key(s)")
	URL := "http://cray-scsd/v1/bmc/loadcfg"
	data, _, err := postURL(URL, jsonScsdParam, nil)
	scsdReply := scsdList{}
	err = json.Unmarshal(data, &scsdReply)
	if err != nil {
		log.Printf("Error unmarshalling the reply from scsd: %s", err)
		return
	}
	for _, t := range scsdReply.Targets {
		if t.StatusCode != 204 {
			log.Printf("scsd FAILED to deploy ssh key to BMC: %s -> %d %s", t.Xname, t.StatusCode, t.StatusMsg)
		} else {
			log.Printf("scsd deployed ssh console key to: %s", t.Xname)
		}
	}
	// TBD - Beyond just logging the status, determine if there is a more preferred way
	// to deal with any specific failures to deploy a BMC ssh cosole key.
	// Scsd response example:
	//  {"Xname":"x5000c1s2b0","StatusCode":204,"StatusMsg":"OK"}
	// Example errors:
	//  {"Xname":"x5000c2s5b0","StatusCode":422,"StatusMsg":"Target 'x5000c2s5b0' in bad HSM state: Unknown"}
	//  {"Xname":"x5000c3r1b0","StatusCode":500,"StatusMsg":"Internal Server Error"}
	//
	// In addition perhpas we want to keep a map (map[string]string) of hostname to
	// public key as a record of the deployment success or errors on a per
	// BMC and public key basis.  This could be used in the future to reduce the time
	// to redeploy all keys.
}

// All the ways a string could be interpreted as 'true'
func isTrue(str string) bool {
	// convert to lower case to remove capitalization as an issue
	lStr := strings.ToLower(str)

	// deal with one char possible values for true
	if len(lStr) == 1 && (lStr[0] == 't' || lStr[0] == '1') {
		return true
	}

	// deal with multiple char possible values for true
	if len(lStr) > 1 && lStr == "true" {
		return true
	}

	// treat everything else as false
	return false
}

// Create the log rotation configuration file
func createLogRotateConf(fileSize string, numRotate int) {
	// This is the default format supplied by the install of
	// the conman package.
	// NOTE: conmand needs the '-HUP' signal to reconnect to
	//  log files after they have been moved/removed.  We will
	//  do that ourselves so are removing it from the conf file.
	/*
		# /var/log/conman/* {
		#   compress
		#   missingok
		#   nocopytruncate
		#   nocreate
		#   nodelaycompress
		#   nomail
		#   notifempty
		#   olddir /var/log/conman.old/
		#   rotate 4
		#   sharedscripts
		#   size=5M
		#   weekly
		#   postrotate
		#     /usr/bin/killall -HUP conmand
		#   endscript
		# }
	*/

	// Open the file for writing
	log.Printf("Opening conman log rotation configuration file for output: %s", logRotConfFile)
	lrf, err := os.Create(logRotConfFile)
	if err != nil {
		// log the problem and panic
		log.Printf("Unable to open config file to write: %s", err)
	}
	log.Printf("Opened %s", logRotConfFile)
	defer lrf.Close()

	// Write out the contents of the file
	fmt.Fprintln(lrf, "# Auto-generated logman configuration file.")
	fmt.Fprintln(lrf, "/var/log/conman/* { ")
	//fmt.Fprintln(lrf, "  compress") // need gzip installed or figure out gpg-zip command line
	fmt.Fprintln(lrf, "  nocompress")
	fmt.Fprintln(lrf, "  missingok")
	fmt.Fprintln(lrf, "  nocopytruncate")
	fmt.Fprintln(lrf, "  nocreate")
	fmt.Fprintln(lrf, "  nodelaycompress")
	fmt.Fprintln(lrf, "  nomail")
	fmt.Fprintln(lrf, "  notifempty")
	fmt.Fprintln(lrf, "  olddir /var/log/conman.old")
	fmt.Fprintf(lrf, "  rotate %d\n", numRotate)
	fmt.Fprintf(lrf, "  size=%s\n", fileSize)
	fmt.Fprintln(lrf, "}")
	fmt.Fprintln(lrf, "")
}

// Parse the timestamp from the input line
func parseTimestamp(line string) (string, time.Time, bool, bool) {
	// NOTE: we are expecting a line in the format of:
	//  "/var/log/conman/console.xname" YYYY-MM-DD-HH-MM-SS
	var nodeName string
	var fd time.Time
	isCon := false
	isAgg := false

	// if the line does not have a valid console log name, skip
	const filePrefix string = "/var/log/conman/console."
	timeStampStr := ""
	pos := strings.Index(line, filePrefix)
	nodeStPos := 0
	if pos != -1 {
		// found a node log file - pull out the node name and time stamp string
		nodeStPos = pos + len(filePrefix)

		// pull out the node name
		posQ2 := strings.Index(line[nodeStPos:], "\"")
		if posQ2 == -1 {
			// unexpected - should be a " char at the end of the filename
			log.Printf("  Unexpected file format - expected quote to close filename")
			return nodeName, fd, isCon, isAgg
		}

		// reindex for position in entire line and split
		posQ2 += nodeStPos
		nodeName = line[nodeStPos:posQ2]
		timeStampStr = line[posQ2+2:]
		isCon = true
	} else {
		// see if this is the console aggregation log file
		pos = strings.Index(line, conAggLogFile)
		if pos == -1 {
			// no log files on this line
			return nodeName, fd, isCon, isAgg
		}

		// we are dealing with the console aggregation log
		nodeName = "consoleAgg.log"
		isAgg = true

		// pull out the position of the timestamp
		timeStampStr = line[len(conAggLogFile)+pos+2:]
	}

	//log.Printf("  String parse - nodeName:%s, timeString:%s",nodeName, timeStampStr)
	// process the line
	var year, month, day, hour, min, sec int
	_, err := fmt.Sscanf(timeStampStr, "%d-%d-%d-%d:%d:%d", &year, &month, &day, &hour, &min, &sec)
	if err != nil {
		// log the error and skip processing this line
		log.Printf("Error parsing timestamp: %s, %s", timeStampStr, err)
		return nodeName, fd, false, false
	}
	// current timestamp of this log rotation entry
	fd = time.Date(year, time.Month(month), day, hour, min, sec, 0, time.Local)

	//log.Printf("  NodeName:%s, timestamp:%s", nodeName, fd.String())

	return nodeName, fd, isCon, isAgg
}

// Function to collect most recent log rotation timestamps
func readLogRotTimestamps(fileStamp map[string]time.Time) (conChanged, aggChanged bool) {
	// read the timestamps from the log rotation state file
	// NOTE: the state file has the format:
	//  "full/path/to/file" Y-M-D-H:M:S

	log.Printf("Reading log rotation timestamps")

	// return true if something has changed
	conChanged = false
	aggChanged = false

	// open the state file
	sf, err := os.Open(logRotStateFile)
	if err != nil {
		log.Printf("Unable to open log rotation state file %s: %s", logRotStateFile, err)
		return false, false
	}
	defer sf.Close()

	// process the lines in the file
	// NOTE: we will only look for files with console.xname
	er := bufio.NewReader(sf)
	for {
		// read the next line
		line, err := er.ReadString('\n')
		if err != nil {
			// done reading file
			break
		}

		// parse this file timestamp
		if fileName, fd, isCon, isAgg := parseTimestamp(line); isCon || isAgg {
			// see if this file already is in the map
			if _, ok := fileStamp[fileName]; ok {
				// entry present, check for timestamp equality
				if fileStamp[fileName] != fd {
					// update and mark change
					fileStamp[fileName] = fd
					if isCon {
						conChanged = true
					} else {
						aggChanged = true
					}
				}
			} else {
				// not already present in the map so add it and mark change
				log.Printf("  %s new file - added to map", fileName)
				fileStamp[fileName] = fd
				if isCon {
					conChanged = true
				} else {
					aggChanged = true
				}
			}
		}
	}

	return conChanged, aggChanged
}

// Function to periodically do the log rotation
func doLogRotate(checkFreqSec int) {
	// turn the check frequency into a valid time duration
	sleepSecs := time.Duration(300) * time.Second
	if checkFreqSec > 0 {
		// make sure we have a valid number before converting
		sleepSecs = time.Duration(checkFreqSec) * time.Second
	} else {
		log.Printf("Log rotation freqency invalid, defaulting to 5 min. Input value:%d", checkFreqSec)
	}

	// keep track of last rotate time for all log files - need to kick
	// conmand if any log files changed.
	fileStamp := make(map[string]time.Time)
	readLogRotTimestamps(fileStamp)

	// loop forever waiting the correct period between checking for log rotations
	for {
		// kick off the log rotation command
		// NOTE: using explicit state file to insure it is on pvc storage and
		//  to be able to parse it after completion.
		log.Print("Starting logrotate")
		cmd := exec.Command("logrotate", "-s", logRotStateFile, logRotConfFile)
		exitCode := -1
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				exitCode = ee.ProcessState.ExitCode()
				log.Printf("Exit Errro: %s", ee)
			}
		} else {
			exitCode = 0
		}
		log.Printf("Log Rotation completed with exit code: %d", exitCode)

		// see if files were actually rotated - kick conmand if needed
		if conChanged, aggChanged := readLogRotTimestamps(fileStamp); conChanged || aggChanged {
			// conman must be signaled to reconnect to moved log files
			if conChanged {
				log.Print("Log files rotated, signaling conmand")
				signalConman()
			}

			// the aggregation log must be restarted for moved file
			if aggChanged {
				respinAggLog()
			}

			// have to restart the fake log file generation as well
			if debugOnly {
				go createTestLogFiles(false)
			}
		} else {
			log.Print("No log files changed with logrotate")
		}

		// sleep until the next check time
		time.Sleep(sleepSecs)
	}
}

// Initialize and start log rotation
func logRotate() {
	// Set up the 'backups' directory for logrotation to use
	log.Printf("Ensuring log rotation backup dir is present:%s", logRotDir)
	_, err := os.Stat(logRotDir)
	if os.IsNotExist(err) {
		emd := os.MkdirAll(logRotDir, 0755)
		if emd != nil {
			log.Printf("Error creating logrotation backup dir:%s", err)
		}
	}

	// default log rotation values
	var enableRotation bool = true
	var fileSize string = "5M"
	var checkFreqSec = 600 // number of seconds between log rotation checks
	var numRotate = 2      // number of copies to keep

	// Check for log rotation env vars
	if val := os.Getenv("LOG_ROT_ENABLE"); val != "" {
		log.Printf("Found LOG_ROT_ENABLE: %s", val)
		enableRotation = isTrue(val)
	}
	if val := os.Getenv("LOG_ROT_FILE_SIZE"); val != "" {
		log.Printf("Found LOG_ROT_FILE_SIZE: %s", val)
		fileSize = val
	}
	if val := os.Getenv("LOG_ROT_SEC_FREQ"); val != "" {
		log.Printf("Found LOG_ROT_SEC_FREQ: %s", val)
		envFreq, err := strconv.Atoi(val)
		if err != nil {
			log.Printf("Error converting log rotation freqency - expected an integer:%s", err)
		} else {
			checkFreqSec = envFreq
		}
	}
	if val := os.Getenv("LOG_ROT_NUM_KEEP"); val != "" {
		log.Printf("Found LOG_ROT_NUM_KEEP: %s", val)
		envNum, err := strconv.Atoi(val)
		if err != nil {
			log.Printf("Error converting log rotation freqency - expected an integer:%s", err)
		} else {
			numRotate = envNum
		}
	}

	// override settings for debug only
	if debugOnly {
		fileSize = "150K"
		checkFreqSec = 10

		// kick off a process to create fake log files
		go createTestLogFiles(true)
	}

	// if not enabled just bail
	if !enableRotation {
		log.Printf("Log rotation not enabled")
		return
	}

	// log the log rotation parameters
	log.Printf("Log rotation enabled, File Size:%s, Check Freq Sec: %d, Num Keep: %d", fileSize, checkFreqSec, numRotate)

	// Create the log rotation configuration file
	createLogRotateConf(fileSize, numRotate)

	// Start the log rotation thread
	go doLogRotate(checkFreqSec)
}

// Function to create and add to log files
func createTestLogFiles(startWatch bool) {
	var sleepTime time.Duration = 1 * time.Second

	file1, _ := os.OpenFile("/var/log/conman/console.test1", os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0600)
	file2, _ := os.OpenFile("/var/log/conman/console.test2", os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0600)
	log1 := log.New(file1, "", log.LstdFlags)
	log2 := log.New(file2, "", log.LstdFlags)

	if startWatch {
		go watchConsoleLogFile("test1")
		go watchConsoleLogFile("test2")
	}
	// start a loop that runs forever to write to the log files
	for {
		// write out some bulk
		log1.Print("Start new write:")
		log2.Print("Start new write:")
		for i := 0; i < 10; i++ {
			log1.Print("Log1: ASAS:LDL:KJFSADSDfDSLKJYUIYHIUNMNKJHSDFKJHDSLKJDFHLKJDSFHASKAJUHSDAASDLKJFHLKJHADSLKJDSHFLKJDHFSD:OUISDFLKDJFHASLJKFHDKJFH")
			log1.Print("Log1: ASAS:LDL:KJFSADSDfDSLKJYUIYHIUNMNKJHSDFKJHDSLKJDFHLKJDSFHASKAJUHSDAASDLKJFHLKJHADSLKJDSHFLKJDHFSD:OUISDFLKDJFHASLJKFHDKJFH")
			log2.Print("Log2: ASAS:LDL:KJFSADSDfDSLKJYUIYHIUNMNKJHSDFKJHDSLKJDFHLKJDSFHASKAJUHSDAASDLKJFHLKJHADSLKJDSHFLKJDHFSD:OUISDFLKDJFHASLJKFHDKJFH")
		}

		// wait before writing out again
		time.Sleep(sleepTime)
	}

	log.Print("LOGGER TEST EXITED")
}

// global var to help with local running/debugging
var debugOnly bool = false
var command *exec.Cmd = nil

// Main loop for the application
func main() {
	// NOTE: this is a work in progress starting to restructure this application
	//  to manage the console state - watching for hardware changes and
	//  updating / restarting the conman process when needed

	// parse the command line flags to the application
	flag.BoolVar(&debugOnly, "debug", false, "Run in debug only mode, not starting conmand")
	flag.Parse()

	// log the fact if we are in debug mode
	if debugOnly {
		log.Print("Running in DEBUG-ONLY mode.")
	}

	// keep track of the nodes
	trackedRvrNodes := make(map[string]bool) // xname,tracking
	trackedMtnNodes := make(map[string]bool) // xname,tracking

	// start the aggregation log
	respinAggLog()

	// Initialize and start log rotation
	logRotate()

	// set up a separate logger object for aggregating the console logs
	// NOTE: this logger is thread safe, set to not append any additional
	//  information per line, and to overwrite the file at conAggLogFile
	//  on startup.
	//calf, err := os.OpenFile(conAggLogFile, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0600)
	//if err != nil {
	//	log.Printf("Could not open console aggregate log file: %s", err)
	//} else {
	//	conAggLogger = log.New(calf, "", 0)
	//	conAggLogger.Print("Starting aggregation log")
	//}

	// Set up the zombie killer
	go watchForZombies()

	// create a loop to execute the conmand command
	forceConfigUpdate := true
	for {
		// Set up or update the conman configuration file.
		// NOTE: do not let the user skip the update the first time through
		rvrNodes, mtnNodes, nodes := updateConfigFile(forceConfigUpdate)
		forceConfigUpdate = false

		// keep track of how many nodes are being watched
		// NOTE: conmand will produce an error if there are no nodes
		numNodes := len(rvrNodes) + len(mtnNodes)
		log.Printf("Number of nodes configured: %d", numNodes)

		// update the list of tracked files and track new ones
		for _, node := range rvrNodes {
			if _, ok := trackedRvrNodes[node]; !ok {
				// record being tracked and forward log file contents
				trackedRvrNodes[node] = true
				go watchConsoleLogFile(node)
			}
		}
		for _, node := range mtnNodes {
			if _, ok := trackedMtnNodes[node]; !ok {
				// record being tracked and forward log file contents
				trackedMtnNodes[node] = true
				go watchConsoleLogFile(node)
			}
		}

		// Make sure that we have a proper ssh console keypair deployed
		// here and on the Mountain BMCs before starting conman.
		ensureMountainConsoleKeysDeployed(nodes)

		// start the conmand process
		// NOTE: this function will not exit until the process exits, and will
		//  spin up a new one on exit.  This will allow a user to manually
		//  kill the conmand process and this will restart while re-reading
		//  the configuration file.
		if debugOnly {
			// not really running, just give a longer pause before re-running config
			time.Sleep(5 * time.Minute)
		} else if numNodes == 0 {
			// nothing found, don't try to start conmand
			log.Printf("No console nodes found - trying again")
			time.Sleep(30 * time.Second)
		} else {
			// looks good to start the conmand process
			executeConman()
		}

		// There are times we want to wait for a little before starting a new
		// process - ie killproc may get caught trying to kill all instances
		time.Sleep(10 * time.Second)
	}
}
