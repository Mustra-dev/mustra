# Automate with the API
<!-- group: Run mustra; order: 64; pages: /api-docs -->

Everything the console does, the API does too. Use it from scripts, your ticketing system or your SIEM.

## Create a token

1. **Administration → API Tokens**, under **New token**.
2. Give it a name that says what uses it, and an expiry.
3. Tick only the permissions it needs. **See the fleet** (`fleet.read`) is needed to read anything; add, for example, **Deploy software and run actions** only if the script deploys.
4. Create it and copy the token. It is shown **once**.

A token never has administrator rights, and never more permissions than the person who made it.

## Call the API

Send the token in the `Authorization` header:

```
curl -H "Authorization: Bearer $MUSTRA_TOKEN" https://mustra.example.com/api/agents
```

```
Invoke-RestMethod -Headers @{ Authorization = "Bearer $env:MUSTRA_TOKEN" } -Uri https://mustra.example.com/api/agents
```

## The API reference

**API Reference** (in the rail, under Administration) lists every route, the permission it needs, its parameters and an example request and response. Its request builder writes the call for you in cURL, PowerShell, Python, JavaScript, TypeScript, Go or C#.

Download the OpenAPI description from the same page (`/api/openapi.json` or `/api/openapi.yaml`) to import into Postman or Insomnia, or to generate a client.

## Good practice

- One token per system, so you can revoke one without breaking the others.
- Give it an expiry, and rotate it before then.
- Everything a token does is in the audit log under the token's name.
