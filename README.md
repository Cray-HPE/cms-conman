# Conman logging service

Conman retrieves the logs from the components it is directed at.
It deposits them the a specified log directory, /var/log/conman.
The get_bmc_ip_addresses script will configure conman to get the 
consoles from compute nodes.  It will get the IP addresses from the
Hardware State Manager.

## Environment Variables
The following environment variables are used by this image.

API_GATEWAY    -- API Gateway domain
RF_ENDPOINT    -- Redfish Endpoint URL
LOG_IDENTIFIER -- controls the name of the console file for an individual node.  
                  It defaults to the node's hostname if none is supplied.
                  This identifier corresponds to fields in the Hardware State 
                  Manager's RedfishEndpoint element.

## Container Requirements
The user name and password to access the nodes' BMCs must be accessible at 
locations indicated by USER_FILE and PWD_FILE with the container.

## PORTS
The conman daemon, conmand, listens on port 7890.

## Restarting conman daemon
The configure_conman application stays running and will monitor the conmand
process.  To restart conman and pick up any hardware changes since the last
restart, just kill the running conmand process.  It will automatically 
run the configuration to check for current hardware and restart conmand.
```bash
sh-4.4# ps -ax
    PID TTY      STAT   TIME COMMAND
      1 ?        Ssl    0:00 /app/configure_conman
    114 pts/0    Ss     0:00 sh
   1042 ?        Sl     0:00 conmand -F -v -c /etc/conman.conf
   1060 pts/0    R+     0:00 ps -ax
sh-4.4# kill 1042
```
The benefit to restarting and refreshing the configuration in this manner is
that it only takes seconds to restart while a complete pod restart can take
quite a bit longer.

When the conmand process is restarted it will sever all existing console 
connections.

## Manual changes to the conman configuration file
Inside the pod, the base configuration file is located at /app/conman_base.conf.
This file is copied in its entirety for the begining of the /etc/conman.conf file
used to start the conmand process.  The individual console connection configurations
are added after the base file contents.  The file at /etc/conman.conf is overwritten
and all manual changes are lost when the process is restarted.

In order to make and preserve manual changes to the /etc/conman.conf file, modify the
first line of the /app/conman_base.conf file to:
```
# UPDATE_CONFIG=FALSE
```
This will prevent the automatic configuration update from happening and the conmand
process will be restarted with the existing /etc/conman.conf file.  To re-enble the
automatic updates again, revert the first line of /app/conman_base.conf to:
```
# UPDATE_CONFIG=TRUE
```


## Build and run the Docker image
This will not likely work on a non-Cray environment because conman will exit
if it does have any nodes to contact. However, it is worthwhile to see it get that far.
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
See cms-tools repo for details on running CT tests for this service.

## Versioning
Use [SemVer](http://semver.org/). The version is located in the [.version](.version) file. Other files either
read the version string from this file or have this version string written to them at build time using the 
[update_versions.sh](update_versions.sh) script, based on the information in the 
[update_versions.conf](update_versions.conf) file.

## Copyright and License
This project is copyrighted by Hewlett Packard Enterprise Development LP and is under the MIT
license. See the [LICENSE](LICENSE) file for details.

When making any modifications to a file that has a Cray/HPE copyright header, that header
must be updated to include the current year.

When creating any new files in this repo, if they contain source code, they must have
the HPE copyright and license text in their header, unless the file is covered under
someone else's copyright/license (in which case that should be in the header). For this
purpose, source code files include Dockerfiles, Ansible files, RPM spec files, and shell
scripts. It does **not** include Jenkinsfiles, OpenAPI/Swagger specs, or READMEs.

When in doubt, provided the file is not covered under someone else's copyright or license, then
it does not hurt to add ours to the header.
