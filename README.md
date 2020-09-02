# Conman logging service

Conman retrieves the logs from the components it is directed at.
It deposits them the a specified log directory, /var/log/conman.
The get_bmc_ip_addresses script will configure conman to get the 
consoles from compute nodes.  It will get the IP addresses from the
Hardware State Manager.

# Environment Variables
The following environment variables are used by this image.

API_GATEWAY    -- API Gateway domain
RF_ENDPOINT    -- Redfish Endpoint URL
LOG_IDENTIFIER -- controls the name of the console file for an individual node.  
                  It defaults to the node's hostname if none is supplied.
                  This identifier corresponds to fields in the Hardware State 
                  Manager's RedfishEndpoint element.

# Container Requirements
The user name and password to access the nodes' BMCs must be accessible at 
locations indicated by USER_FILE and PWD_FILE with the container.

# PORTS
The conman daemon, conmand, listens on port 7890.

# Build and run the Docker image
# This will not likely work on a non-Cray environment because conman will exit
# if it does have any nodes to contact.
# However, it is worthwhile to see it get that far.
```bash
>> cd $REPO
>> docker build -t cray_conman .
>> docker run -d  --name cray_conman cray_conman
```
To snoop around in the running container:
```bash
>> docker exec -it cray_conman /bin/bash

>> ls -l /var/log/conman.log 
-rw-r--r-- 1 root root 5620 Nov 14 21:14 /var/log/conman.log

>> ls -l /var/log/conman
total 44
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s14b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s15b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s18b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s22b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s24b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s25b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s26b0
-rw------- 1 root root 71 Nov 14 21:05 console.x0c0s27b0
-rw------- 1 root root 70 Nov 14 21:05 console.x1c0s0b0
-rw------- 1 root root 70 Nov 14 21:05 console.x1c0s1b0
-rw------- 1 root root 70 Nov 14 21:05 console.x1c0s2b0

## Testing

### CT Tests
CT tests can be found in /ct-tests

On a physical system, CMS tests can be found in /opt/cray/tests/crayctl-stage{NUMBER}/cms
Please see https://connect.us.cray.com/confluence/display/DST/Stage+Tests+Guidelines for more details.

example: run CT test for conman at crayctl stage 4
```
# /opt/cray/tests/crayctl-stage4/cms/conman_stage4_ct_tests.sh or
# cmsdev test conman --ct
```

Tests return 0 for success, 1 otherwise
