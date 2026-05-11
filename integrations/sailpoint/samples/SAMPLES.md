# SailPoint ISC — Sample Data

This directory is used by the OAA Dry-Run Tester to validate the integration
without pushing to a live Veza environment.

The SailPoint integration uses a **live REST API** (not flat files), so there
are no CSV/XLSX samples to place here. The dry-run test runs the script with
`--dry-run --save-json`, which authenticates to the real SailPoint API and
saves the OAA payload JSON locally without pushing to Veza.

## To run a dry-run test

Ensure your `.env` file is configured with valid SailPoint credentials, then:

```bash
cd integrations/sailpoint
python3 sailpoint.py --env-file .env --dry-run --save-json --log-level DEBUG
```

The OAA payload will be saved as `sailpoint_oaa_payload_<timestamp>.json`
in the `integrations/sailpoint/` directory.

## If you want to test without real credentials

You can place representative JSON fixtures here to use in unit tests or
offline validation:

| File | Description |
|------|-------------|
| `identities.json` | Sample `GET /v3/identities` response (array of identity objects) |
| `roles.json` | Sample `GET /v3/roles` response (array of role objects with `accessProfiles[]`) |
| `role_assignments.json` | Sample `GET /v3/roles/{id}/assigned-identities` response |
| `access_profiles.json` | Sample `GET /v3/access-profiles` response |

### Minimum identity object

```json
[
  {
    "id": "ff80818155fe8c080155fe8d925b0316",
    "name": "Jane Doe",
    "alias": "jane.doe",
    "emailAddress": "jane.doe@example.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "status": "ACTIVE",
    "isManager": false,
    "manager": { "id": "abc123", "name": "John Manager" },
    "lifecycleState": { "stateName": "active" }
  }
]
```

### Minimum role object

```json
[
  {
    "id": "2c91808a7190d06e01719938fcd20792",
    "name": "Engineering Read-Only",
    "enabled": true,
    "requestable": true,
    "owner": { "id": "ff80818155fe8c080155fe8d925b0316", "name": "Jane Doe" },
    "accessProfiles": [
      { "id": "2c91808a7190d06e01719938fcd20793", "name": "GitHub Access" }
    ]
  }
]
```

### Minimum access profile object

```json
[
  {
    "id": "2c91808a7190d06e01719938fcd20793",
    "name": "GitHub Access",
    "enabled": true,
    "requestable": true,
    "owner": { "id": "ff80818155fe8c080155fe8d925b0316", "name": "Jane Doe" },
    "source": { "id": "src001", "name": "GitHub" },
    "entitlements": [
      { "id": "ent001", "name": "GitHub:read" }
    ]
  }
]
```
