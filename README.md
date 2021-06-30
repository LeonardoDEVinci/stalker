# Stalker
Stalker is a web based Sysmon log analysis platform. It was designed to be used in a malware analysis environment and make following specific processes easier. It uses

- Django - web interface
- Elasticsearch - log storage
- Winlogbeat - sending logs to Elasticsearch
- Nginx - reverse proxy

and is built on Docker and Docker Compose.

## Installation
Clone the git repo.
```bash
git clone https://github.com/LeonardoDEVinci/stalker
```

From inside the cloned directory, edit the `.env` file and change the variables to the appropriate values.

You will probably have to add `vm.max_map_count=262144` to bottom of `/etc/sysctl.conf` for Elasticsearch to work.

Build and run with docker.
```bash
docker-compose build && docker-compose up -d
```

You should now be able to access the web interface from either the HTTP or HTTPS port that you set in `.env`.

## Winlogbeat Install
While logged in, go to the `manage` page and create a password for the Winlogbeat user. Then go to the machine with Sysmon installed and go to the `downloads` page. Download and run the script. This script does not install Sysmon and assumes sysmon will be installed separately.

