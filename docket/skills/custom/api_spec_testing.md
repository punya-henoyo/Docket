# Skill: API spec testing

Given an OpenAPI/Swagger spec, treat it as an attack surface map, not documentation.

1. Enumerate every path + method + parameter, including ones the UI never calls.
2. Prioritise: parameters that name identifiers (`id`, `user`, `account`) for IDOR;
   anything reaching a query, command, path, or template for injection.
3. For each endpoint, test the AUTHENTICATED and UNAUTHENTICATED cases — an endpoint
   that works without a token is a finding in itself.
4. Spec-declared types are claims, not constraints. Send the wrong type, an oversized
   value, and a null for each field.
