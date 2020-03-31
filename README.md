ckanext-authz-service
=====================
**JSON Web Tokens (JWT) Based Authorization API for CKAN**

This extension uses CKAN's built-in authentication and authorization
capabilities to generate JWT tokens and provide them via CKAN's Web API to
clients. This is useful in situations where clients need to integrate with an
external system or service which can consume JWT tokens and has to rely on
CKAN for authentication and authorization.

By designating "glue" authorization check functions using a simple decorator
API, this extension maps CKAN entities and permissions to scopes encoded into
generated JWT tokens. This allows tokens to relay both the user's identity and
the permissions granted to them to act on different entities such as 
organizations and datasets.  

Other CKAN extensions can customize the authorization functions used to 
determine a user's access level, or define custom entity types to support.

Requirements
------------

This extension works with CKAN 2.8.x. 

It may work, but has not been tested, with other CKAN versions. 


Installation
------------

To install ckanext-authz-service:

1. Activate your CKAN virtual environment, for example:
```
     . /usr/lib/ckan/default/bin/activate
```

2. Install the ckanext-authz-service Python package into your virtual environment:
```
     pip install ckanext-authz-service
```

3. Add `authz_service` to the `ckan.plugins` setting in your CKAN
   config file (by default the config file is located at
   `/etc/ckan/default/production.ini`).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:
```
     sudo service apache2 reload
```

API
---
This extension provides 3 new API endpoints:

### `authorize` 
Ask for a JWT token authorizing the current user to perform some actions on 
specific objects. 

#### HTTP Method: `POST`

#### Parameters:

* `scopes` (list of strings, required) - list of requested permission scopes. 
See [scopes](#Scopes) below for details.
    
* `lifetime` (int, optional) - requested token lifetime in seconds. Note that 
if this exceeds the maximal lifetime configured for the server, the server's 
maximal lifetime will be used instead. 

#### Response:

A successful response will include a JWT token, as well as the information 
encoded into the token in accessible format:

* `token` - the encoded / signed / encrypted JWT token
* `user_id` - the authorized user name
* `expires_at` - token expiration time in ISO-8601 format
* `requested_scopes` - list of permission scopes requested
* `granted_scopes` - list of permission scopes granted

`granted_scopes` may be different from `requested_scopes` based on the server's
decision. 

### `verify`
Verify a JWT token and show all it's claims

#### HTTP Method: `GET` or `POST`

#### Parameters:

* `token` (string, required) - the JWT token to verify
* `strict` (boolean, optional, defaults to `true`) - If set to `false`, attempt
to provide JWT payload even if the token is invalid (e.g. is expired or has 
invalid issuer). 

#### Response:

TBD

### `public_key`
Get the public key that can be used to verify / decrypt a JWT token provided
by this extension. This is only available if an asymmetric JWT algorithm is in
use and a public key has been configured. 

This allows 3rd party services that want to rely on tokens provided by CKAN to
get the current verification key (and most likely cache it internally) without
having it pre-configured. 

#### HTTP Method: `GET` or `POST`

#### Response:

```json
{
  "public_key": "<... public key contents ...>"
}
```

Authorization Scopes
--------------------
"Scopes" in the context of `authz-service` represent permission to perform one
or more actions on one or more entities.

A scope is represented as a string of between 1 and 4 colon separated parts, of
one of the following structures:

    <entity_type>[:entity_id[:action]]

or:

    <entity_type>[:entity_id[:subscope[:action]]]

That is, a 3-part scope represents an entity type, an entity ID and an action;
While a 4-part scope represets an entity type, an entity ID, a subscope and an
action.

`entity_type` is the only required part, and represents the type of entity on
which actions can be performed.

`entity_id` is optional, and can be used to limit the scope of actions to a
specific entity (rather than all entities of the same type).

`action` is optional, and can be used to limit the scope to a specific action
(such as 'read' or 'delete'). Omitting typically means "any action".

`subscope` is optional and can further limit actions to a "sub-entity", for
example a dataset's metadata or an organization's users.

Each optional part can be replaced with a `*` if a following part is to be
specified, or simply omitted if no following parts are specified as well.

To specify "all actions" in a scope that has a subscope, the `*` representing
"all actions" must not be omitted, to ensure that the scope string has 4 parts.

### Examples:

* `org:*:read` - denotes allowing the "read" action on all "org" type entities.

* `org:foobar:*` - denotes allowing all actions on the 'foobar' org.
`org:foobar` means the exact same thing.

* `ds:*:metadata:read` - denotes allowing reading the metadata of all dataset
entities.

* `ds:*:metadata:*` - denotes allowing all actions on the metadata of all
dataset entities.

### Default CKAN Entities and Actions:

The following table lists CKAN entity types, subscopes and actions that are preconfigured:

| CKAN Entity  | Entity type | Subscope   | Entity Actions                               | Global Actions   |
|--------------|-------------|------------|----------------------------------------------|------------------|
| Organization | `org`       |            | `read`, `update`, `delete`, `patch`, `purge` | `create`, `list` |
| Organization | `org`       | `member`   | `create`, `delete`                           |                  |
| Dataset      | `ds`        |            | `read`, `update`, `delete`, `patch`, `purge` | `create`         |
| Dataset      | `ds`        | `data`     | `read`, `update`, `patch`                    |                  |
| Dataset      | `ds`        | `metadata` | `read`, `update`, `patch`                    |                  |
| Resource     | `res`       |            | `read`, `update`, `delete`, `patch`          |                  |
| Resource     | `res`       | `data`     | `read`, `update`                             |                  |
| Resource     | `res`       | `metadata` | `read`, `update`                             |                  |

Configuration can be changed by replacing the permissions mapping file with a new one. 

Configuration settings
----------------------

### JWT settings

**NOTE**: From the settings below, you *must* set either `jwt_private_key` or
`jwt_private_key_file`. You probably also want to set `jwt_public_key_file`. 
All other configuration options are optional. 
 
#### `ckanext.authz_service.jwt_private_key` (String)

Private key or secret key for JWT signing / encryption. This should contain
the key as a string. If both this value and `jwt_private_key_file` are set, 
this one will take precedence.

#### `ckanext.authz_service.jwt_private_key_file` (File Path String)

Path to the private key file. This is typically used with asymmetric signing /
encryption algorithms. If both this value and `jwt_private_key` are set, 
this value will be ignored. 

#### `ckanext.authz_service.jwt_algorithm` (String)

Set the JWT signing / encryption algorithm. Defaults to `RS256` if not provided. 
Possible values:

* TBD

#### `ckanext.authz_service.jwt_public_key_file` (File path String)

File path of the JWT public key file if an asymmetric signing / encryption
algorithm has been used. 

If not set, the `public_key` and `verify` API commands will not work. 

#### `ckanext.authz_service.jwt_max_lifetime` (Integer)

Maximal JWT token lifetime in seconds. Defaults to 900 (15 minutes) if not 
set. Users can request tokens with shorter lifetime than this value.

#### `ckanext.authz_service.jwt_issuer` (String)

Value of the JWT `iss` claim; Defaults to the current site URL if not set. 

#### `ckanext.authz_service.jwt_audience` (String)

Value of the JWT `aud` claim; If not set, tokens will not include the `aud`
claim. 

#### `ckanext.authz_service.jwt_include_user_email` (Boolean)

Whether to include the user's email address in JWT tokens as the `email` claim.
Defaults to `False`.

#### `ckanext.authz_service.jwt_include_token_id` (Boolean)

Whether to include a unique ID as the JWT `jti` claim. Useful if consumers
want to ensure a token has not been replayed. 
Defaults to `False`.

Developer installation
----------------------

To install ckanext-authz-service for development, activate your CKAN virtualenv and
do:

    git clone https://github.com/datopian/ckanext-authz-service.git
    cd ckanext-authz-service
    python setup.py develop
    pip install -r dev-requirements.txt


### Generating an RSA keypair for RS* signing & encryption

If you want to use the RS* signing / encryption algorithms, here is how to quickly
generate an RSA keypair for local testing / development purposes:


    # Generate an RSA private key in PEM encoded format
    ssh-keygen -t rsa -b 4096 -m PEM -f jwt-rs256.key

    # Extract the public key to a PEM file
    openssl rsa -in jwt-rs256.key -pubout -outform PEM -out jwt-rs256.key.pub

Do not enter any passphrase when generating the private key.

Your keys will be saved at `jwt-rs256.pem` (private key) and `jwt-rs256.key.pub` (public key).
You can now set the paths to these files in your config INI file (see above).

Tests
-----

To run the tests, do:

    make test

To run the tests and produce a coverage report, first make sure you have
coverage installed in your virtualenv (``pip install coverage``) then run:

    make coverage

Releasing a new version of ckanext-authz-service
------------------------------------------------

ckanext-authz-service should be available on PyPI as https://pypi.org/project/ckanext-authz-service.
To publish a new version to PyPI follow these steps:

1. Update the version number in the `setup.py` file.
   See [PEP 440](http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers) 
   for how to choose version numbers.

2. Make sure you have the latest version of necessary packages:
```
    pip install --upgrade setuptools wheel twine
```

3. Create a source and binary distributions of the new version:
```
       python setup.py sdist bdist_wheel && twine check dist/*
```

   Fix any errors you get.

4. Upload the source distribution to PyPI:
```
    twine upload dist/*
```

5. Commit any outstanding changes:
```
    git commit -a
```

6. Tag the new release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.1 then do:
```
    git tag 0.0.1
    git push --tags
```