# v1.2

Improved DNS query filtering to avoid situations where certain DNS resolvers would send multiple identical responses.

# v1.1

Added logic to remove the collaborator subdomain from the received answer. In certain edge cases, an extra DNS query is made and the subdomain was being added.

# v1.0

Initial Release
