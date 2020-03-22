ckanext-jwt-authz-api
=====================
**JSON Web Tokens (JWT) Based Authorization API for CKAN**

This extension uses CKAN's built-in authentication and authorization
capabilities to generate JWT tokens and provide them via CKAN's Web API to
clients. This is useful in situations where clients need to integrate with an
external system or service which can consume JWT tokens and has to rely on
CKAN for authentication and authorization.

Using a customizable configuration file, this extension maps CKAN entities and
permissions to scopes encoded into generated JWT tokens, so that tokens relay
both the user's identity, and the permissions granted to them to act on
different entities such as organizations and datasets.  Scopes can even relate
to custom entities unknown to CKAN, as long as deciding the access level a user
should have to these entities can be determined based on their permissions in
CKAN.

Requirements
------------

This extension works with CKAN 2.8.x. 

It may work, but has not been tested, with other CKAN versions. 


Installation
------------

To install ckanext-jwt-authz-api:

1. Activate your CKAN virtual environment, for example:
```
     . /usr/lib/ckan/default/bin/activate
```

2. Install the ckanext-jwt-authz-api Python package into your virtual environment:
```
     pip install ckanext-jwt-authz-api
```

3. Add `jwt-authz-api` to the `ckan.plugins` setting in your CKAN
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

TBD

#### Response:

TBD

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

Configuration settings
----------------------

### Permission Mapping

#### `ckanext.jwt_authz_api.permissions_map_file` (File Path String)

Path to an **Authzzie** permissions mapping YAML file. This file configures 
`authzzie`, which is the permissions mapping library at the core of this 
extension. 

See [Permissions Mapping](#Permissions-Mapping) below for more details on the
format of this file. 

If none is provided, will default to the `default-permissions-map.yaml` file
bundled with the extension.

### JWT settings

**NOTE**: From the settings below, you *must* set either `jwt_private_key` or
`jwt_private_key_file`. You probably also want to set `jwt_public_key_file`. 
All other configuration options are optional. 
 
#### `ckanext.jwt_authz_api.jwt_private_key` (String)

Private key or secret key for JWT signing / encryption. This should contain
the key as a string. If both this value and `jwt_private_key_file` are set, 
this one will take precedence.

#### `ckanext.jwt_authz_api.jwt_private_key_file` (File Path String)

Path to the private key file. This is typically used with asymmetric signing /
encryption algorithms. If both this value and `jwt_private_key` are set, 
this value will be ignored. 

#### `ckanext.jwt_authz_api.jwt_algorithm` (String)

Set the JWT signing / encryption algorithm. Defaults to `RS256` if not provided. 
Possible values:

* TBD

#### `ckanext.jwt_authz_api.jwt_public_key_file` (File path String)

File path of the JWT public key file if an asymmetric signing / encryption
algorithm has been used. 

If not set, the `public_key` and `verify` API commands will not work. 

#### `ckanext.jwt_authz_api.jwt_issuer` (String)

Value of the JWT `iss` claim; Defaults to the current site URL if not set. 

#### `ckanext.jwt_authz_api.jwt_audience` (String)

Value of the JWT `aud` claim; If not set, tokens will not include the `aud`
claim. 

#### `ckanext.jwt_authz_api.jwt_include_user_email` (Boolean)

Whether to include the user's email address in JWT tokens as the `email` claim.
Defaults to `False`.

#### `ckanext.jwt_authz_api.jwt_include_token_id` (Boolean)

Whether to include a unique ID as the JWT `jti` claim. Useful if consumers
want to ensure a token has not been replayed. 
Defaults to `False`.

Permission Mapping
------------------
See the included `default-permissions-map.yaml` file for an example of how 
default CKAN permissions are mapped. 

More details TBD


Developer installation
----------------------

To install ckanext-jwt-authz-api for development, activate your CKAN virtualenv and
do:

    git clone https://github.com/datopian/ckanext-jwt-authz-api.git
    cd ckanext-jwt-authz-api
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

Releasing a new version of ckanext-jwt-authz-api
------------------------------------------------

ckanext-jwt-authz-api should be available on PyPI as https://pypi.org/project/ckanext-jwt-authz-api.
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