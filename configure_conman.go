// Copyright 2019-2020 Hewlett Packard Enterprise Development LP

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/hpcloud/tail"
	compcreds "stash.us.cray.com/HMS/hms-compcredentials"
	sstorage "stash.us.cray.com/HMS/hms-securestorage"
)

// Location of the configuration file
const baseConfFile string = "/app/conman_base.conf"
const confFile string = "/etc/conman.conf"
const conAggLogFile string = "/var/log/conman/consoleAgg.log"

// Location of the Mountain BMC console ssh key pair files.
// These are obtained or generated when the pod is created.
const mountainConsoleKey string = "/etc/conman.key"
const mountainConsoleKeyPub string = "/etc/conman.key.pub"

// Global vars
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
func getURL(URL string) ([]byte, error) {
	var err error = nil
	log.Printf("URL: %s\n", URL)
	resp, err := http.Get(URL)
	if err != nil {
		// handle error
		log.Printf("Error on request to %s: %s", URL, err)
		return nil, err
	}
	log.Printf("Response Status code: %d\n", resp.StatusCode)
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Printf("Error reading response: %s", err)
		return nil, err
	}
	//fmt.Printf("Data: %s\n", data)
	return data, err
}

// Helper function to execute an http POST command
func postURL(URL string, requestBody []byte) ([]byte, error) {
	var err error = nil
	log.Printf("URL: %s\n", URL)
	resp, err := http.Post(URL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		// handle error
		log.Printf("Error on request to %s: %s", URL, err)
		return nil, err
	}
	log.Printf("Response Status code: %d\n", resp.StatusCode)
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Printf("Error reading response: %s", err)
		return nil, err
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
		log.Printf("  %s", redEndpoint)
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
		log.Printf("  %s", sc)
	}

	return rp.Components, nil
}

// Look up the creds for the input endpoints
func getPasswords(bmcXNames []string) map[string]compcreds.CompCredentials {
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
		log.Panicf("Error fetching redfish endpoints: %s", err)
	}

	// get the state information to find mountain/river designation
	stComps, err := getStateComponents()
	if err != nil {
		log.Panicf("Error fetching state components: %s", err)
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
		conAggLogger.Printf("console.hostname: %s %s", xname, line.Text)
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
	go logPipeOutput(&cmdStdErr, "stderr")

	// spin a thread to read the stdout pipe
	go logPipeOutput(&cmdStdOut, "stdout")

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

// Obtain Mountain node BMC credentials from Vault.
func vaultGetMountainConsoleCredentials() error {
	// NOTE: Returning false for now since Vault is not available on a system
	// with Mountain hardware.

	// NOTE: The final implementation would obtain the public and private
	// keys and save to /etc/conman.key.pub and /etc/conman.key
	// respectively.  Vault will also need to be asked to generate
	// the keypair should it not exist.
	return errors.New("Vault credental access not implemented yet.")
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
		return errors.New(fmt.Sprintf("Error generating console key pair: %s", err))
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

	// Check that we have key pair files on local storage
	_, err_key := os.Stat(mountainConsoleKey)
	_, err_pub := os.Stat(mountainConsoleKeyPub)
	if os.IsNotExist(err_key) || os.IsNotExist(err_pub) {
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
	data, err := postURL(URL, jsonScsdParam)
	scsdReply := scsdList{}
	err = json.Unmarshal(data, &scsdReply)
	if err != nil {
		log.Printf("Error unmarshalling the reply from scsd: %s", err)
		return
	} else {
		for _, t := range scsdReply.Targets {
			if t.StatusCode != 204 {
				log.Printf("scsd FAILED to deploy ssh key to BMC: %s -> %d %s", t.Xname, t.StatusCode, t.StatusMsg)
			} else {
				log.Printf("scsd deployed ssh console key to: %s", t.Xname)
			}
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

// Main loop for the application
func main() {
	// NOTE: this is a work in progress starting to restructure this application
	//  to manage the console state - watching for hardware changes and
	//  updating / restarting the conman process when needed

	// keep track of the nodes
	trackedRvrNodes := make(map[string]bool) // xname,tracking
	trackedMtnNodes := make(map[string]bool) // xname,tracking

	// set up a separate logger object for aggregating the console logs
	// NOTE: this logger is thread safe, set to not append any additional
	//  information per line, and to overwrite the file at conAggLogFile
	//  on startup.
	calf, err := os.OpenFile(conAggLogFile, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Printf("Could not open console aggregate log file: %s", err)
	} else {
		conAggLogger = log.New(calf, "", 0)
		conAggLogger.Print("Starting aggregation log")
	}

	// Set up the zombie killer
	go watchForZombies()

	// create a loop to execute the conmand command
	forceConfigUpdate := true
	for {
		// Set up or update the conman configuration file.
		// NOTE: do not let the user skip the update the first time through
		rvrNodes, mtnNodes, nodes := updateConfigFile(forceConfigUpdate)
		forceConfigUpdate = false

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
		executeConman()
	}
}
