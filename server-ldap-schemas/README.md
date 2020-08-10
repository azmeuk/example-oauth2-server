# Connect2id server LDAP schemas #

Copyright (c) Connect2id Ltd., 2012 - 2020

LDAP schemas for the [Connect2id server](http://connect2id.com/server) to
persist the following data:

* Details of registered OAuth 2.0 / OpenID Connect clients.
* Long-lived (persisted) authorisation per subject, client ID and optional 
  actor (consent). 
* Identifier-based OAuth 2.0 bearer access tokens.
* Revoked authorisations.
* Subject (end-user) sessions.
* Subject (end-user) session index.


## Supported LDAP servers ##

* OpenDJ
* OpenLDAP
* 389 Directory Server


## Schemas ##

The schema files are located in the `src/main/resources` directory:

* Client registration schema: `oidc-client-schema-[server].ldif`
* Long-lived authorisation and authorisation revocation schema: 
  `oidc-authz-schema-[server].ldif`
* Subject session and subject session index schema: 
  `oidc-session-schema-[server].ldif`

Use `opendj` for OpenDJ and 389 DS.

Use `openldap` for OpenLDAP.


## Licence ##

The LDAP schemas are provided under the terms of the Apache 2.0 licence.

## Sample entry tree ##

![Sample entry tree](https://bytebucket.org/connect2id/server-ldap-schemas/raw/ef1760f5d6322f340d70729425dbd093a474b31d/example-ldap-entry-screenshot.png)

## Questions? ##

Get in touch with Connect2id [support](http://connect2id.com/contact).

2019-03-15
