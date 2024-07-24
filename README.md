# gitsite-comment

A gitsite comment system.

### Local Development

Step 1: create `.dev.vars` under the root path:

```
# vars for dev:
ALWAYS_HTTPS = "false"
OAUTH_PROVIDER = "qq"
OAUTH_CLIENT_ID = "<your-oauth-client-id>"
OAUTH_CLIENT_SECRET = "<your-oauth-client-secret>"
OAUTH_REDIRECT_URI = "http://localhost:8787/oauth_response"

SALT = "any-random-string"

PAGE_ORIGIN = "http://localhost:3000"
PAGE_PATH_PREFIX = ""
```

Step 2: initialize database:

```
$ npx wrangler d1 execute comment-db --local --file=./schema.sql
```

Step 2: start local server:

```
$ npx wrangler dev
```

All changes are made in local.

### Deploy

To create a production env, copy `.dev.vars` to `.production.vars` and make any neccessary changes.

Add production section to `wrangler.toml`:

```
#################### production configuration ####################

[env.production]

name = "<your-worker-name>"

vars = { ENVIRONMENT = "production", ALWAYS_HTTPS = "true", OAUTH_PROVIDER = "<your-oauth-provider>", OAUTH_CLIENT_ID = "<your-oauth-client-id>", OAUTH_REDIRECT_URI = "https://example.com/oauth_response", PAGE_ORIGIN = "https://example.com" }

d1_databases = [
    { binding = "DB", database_name = "comment-db", database_id = "<your-d1-id>" },
]

kv_namespaces = [{ binding = "KV", id = "<your-kv-id>" }]
```

Deploy `production` using following command:

```
$ npx wrangler deploy --env production
```

Make sure the D1 database was initialized by `schema.sql` before deploy.

### I18N Support

Error message is translated to localized message by error code.

For example:

```
{
    "error": "RATE_LIMIT",
    "message": "Please wait a little while."
}
```

Set vars `I18N_RATE_LIMIT=Please wait for a few minutes.` to get localized message.
