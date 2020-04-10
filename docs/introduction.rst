Introduction
************
`ckanext-authz-service` is a CKAN plugin that uses CKAN's built-in
authentication and authorization capabilities to generate JWT tokens and
provide them via CKAN's Web API to clients.

This is useful in situations where clients need to integrate with an
external system or service which can consume JWT tokens and has to rely on
CKAN for authentication and authorization.

By designating "glue" authorization check functions using a simple API,
this extension maps CKAN entities and permissions to scopes encoded into
generated JWT tokens. This allows tokens to relay both the user's identity and
the permissions granted to them to act on different entities such as
organizations and datasets.

Other CKAN extensions can customize the authorization functions used to
determine a user's access level, or define custom entity types to support.
