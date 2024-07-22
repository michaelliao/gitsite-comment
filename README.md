# gitsite-comment

A gitsite comment system.

### Local Development

Step 1: create `.dev.vars` under the root path:

```
# vars for dev:
OAUTH_PROVIDER = "qq"
OAUTH_CLIENT_ID = "your-oauth-client-id"
OAUTH_CLIENT_SECRET = "your-oauth-client-secret"
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

Deploy `production` using following command:

```
$ npx wrangler deploy --env production
```

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
