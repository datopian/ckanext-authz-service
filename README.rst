.. You should enable this project on travis-ci.org and coveralls.io to make
   these badges work. The necessary Travis and Coverage config files have been
   generated for you.

.. image:: https://travis-ci.org/datopian/ckanext-jwt-authz-api.svg?branch=master
    :target: https://travis-ci.org/datopian/ckanext-jwt-authz-api

.. image:: https://coveralls.io/repos/datopian/ckanext-jwt-authz-api/badge.svg
  :target: https://coveralls.io/r/datopian/ckanext-jwt-authz-api

.. image:: https://img.shields.io/pypi/v/ckanext-jwt-authz-api.svg
    :target: https://pypi.org/project/ckanext-jwt-authz-api/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/ckanext-jwt-authz-api.svg
    :target: https://pypi.org/project/ckanext-jwt-authz-api/
    :alt: Supported Python versions

.. image:: https://img.shields.io/pypi/status/ckanext-jwt-authz-api.svg
    :target: https://pypi.org/project/ckanext-jwt-authz-api/
    :alt: Development Status

.. image:: https://img.shields.io/pypi/l/ckanext-jwt-authz-api.svg
    :target: https://pypi.org/project/ckanext-jwt-authz-api/
    :alt: License

=============
ckanext-jwt-authz-api
=============

.. Put a description of your extension here:
   What does it do? What features does it have?
   Consider including some screenshots or embedding a video!

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

------------
Requirements
------------

This extension works with CKAN 2.8.x.

------------
Installation
------------

.. Add any additional install steps to the list below.
   For example installing any non-Python dependencies or adding any required
   config settings.

To install ckanext-jwt-authz-api:

1. Activate your CKAN virtual environment, for example::

     . /usr/lib/ckan/default/bin/activate

2. Install the ckanext-jwt-authz-api Python package into your virtual environment::

     pip install ckanext-jwt-authz-api

3. Add ``jwt-authz-api`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/production.ini``).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload


---------------
Config settings
---------------
*Authzzie* permission mapping configuration file location:

.. # The minimum number of hours to wait before re-checking a resource
   # (optional, default: 24).
   ckanext.jwt_authz_api.some_setting = some_default_value

..
JWT settings:


------------------
Permission Mapping
------------------

.. Some details about the structure of the authzzie permissions map file


----------------------
Developer installation
----------------------

To install ckanext-jwt-authz-api for development, activate your CKAN virtualenv and
do::

    git clone https://github.com/datopian/ckanext-jwt-authz-api.git
    cd ckanext-jwt-authz-api
    python setup.py develop
    pip install -r dev-requirements.txt


-----
Tests
-----

To run the tests, do::

    nosetests --nologcapture --with-pylons=test.ini

To run the tests and produce a coverage report, first make sure you have
coverage installed in your virtualenv (``pip install coverage``) then run::

    nosetests --nologcapture --with-pylons=test.ini --with-coverage --cover-package=ckanext.jwt_authz_api --cover-inclusive --cover-erase --cover-tests


----------------------------------------
Releasing a new version of ckanext-jwt-authz-api
----------------------------------------

ckanext-jwt-authz-api should be available on PyPI as https://pypi.org/project/ckanext-jwt-authz-api.
To publish a new version to PyPI follow these steps:

1. Update the version number in the ``setup.py`` file.
   See `PEP 440 <http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers>`_
   for how to choose version numbers.

2. Make sure you have the latest version of necessary packages::

    pip install --upgrade setuptools wheel twine

3. Create a source and binary distributions of the new version::

       python setup.py sdist bdist_wheel && twine check dist/*

   Fix any errors you get.

4. Upload the source distribution to PyPI::

       twine upload dist/*

5. Commit any outstanding changes::

       git commit -a

6. Tag the new release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.1 then do::

       git tag 0.0.1
       git push --tags
