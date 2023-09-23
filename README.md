# Authelia file database plugin for glauth

This plugin watches the authelia file based user database and provides the information
to glauth. With this you should be able to expose authelia users to applications which are
neither capable of OIDC or proxy auth.

## Example configuration

```
#################
# glauth.conf

#################
# General configuration.
debug = true
#syslog = true

#################
[ldap]
  enabled = true
  listen = "0.0.0.0:3893"

[ldaps]
  enabled = false
  listen = "0.0.0.0:3894"
  cert = "cert.pem"
  key = "key.pem"

#################
# The backend section controls the data store.
[backend]
  datastore = "plugin"
  # If "plugin," uncomment the line below
  plugin = "bin/linuxamd64/authelia.so" # Path to the authelia plugin
  pluginhandler = "NewAutheliaFileHandler" # Name of the plugin handler, do not change
  baseDN = "dc=glauth,dc=com"
  database = "/opt/containers/data/authelia/conf/users_database.yml" # Path to your authelia users file

#################
# Enable and configure the optional REST API here.
[api]
  enabled = true
  tls = false # enable TLS for production!!
  listen = "0.0.0.0:5555"
  cert = "cert.pem"
  key = "key.pem"
```

## Caveats

* Users can only authenticate with their password, this plugin does not support MFA
* UID and GID number are generated during file read and might change between file reads, so do not rely on these
* Updating users and groups via ldap is not possible

