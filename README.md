# apps.grapheneos.org
GrapheneOS application repository

## Custom server setup

The following describes the procedure to create a custom apps repository running on your own server.

### Prerequisites

1. a system with:
    - python3
    - signify
    - a webserver (e.g. nginx)
    - aapt
2. ideally a FQDN (while IP is possible but not recommended for well known reasons)
3. a SSL certificate

### Initial Setup

1. Create your own signing key: `signify -n -G -p apps.0.pub -s apps.0.sec`

2. clone this repository to your server (e.g. `git clone https://github.com/GrapheneOS/apps.grapheneos.org /var/www/html/`)

3. Create the following directories in this cloned directory: `mkdir apps apps-stable apps-beta`

4. install a webserver on your server and ensure it has a valid certificate set (see step 3)
    - the root directory must point to the `apps` directory (e.g. `/var/www/html/apps`)

5. put your app(s) in `apps-stable/` or `apps-beta/` directory 
    - every app must have its own directory (i.e. `apps-stable/<app-package-name>/my-app.apk`)
    - the subdirectory name has to be the unique package name (e.g. `org.myapp.example`)

6. run `./generate.py` to sign and add these apps to your repo

7. modify the Apps app:
    - replace all occurences of `apps.grapheneos.org` with your own FQDN
    - grab the content of your public key from `apps.0.pub` and replace the `PUBLIC_KEY` variable
    - adjust the timestamp to the current one (e.g. `date +%s`)
    - adjust [network_security_config.xml](https://github.com/GrapheneOS/Apps/blob/main/app/src/main/res/xml/network_security_config.xml) if your CA is not already there
    
8. build the Apps app

### Updating your repo

Follow steps 5 + 6
