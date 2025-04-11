# Email and password example with 2FA and WebAuthn in SvelteKit

This is a fork of https://github.com/lucia-auth/example-sveltekit-email-password-webauthn

The only changes are to replace the SQLite implementation with a Postgres implemmentation using Drizzle orm.

Built with Postgres and Drizzle

- Password checks with HaveIBeenPwned
- Sign in with passkeys
- Email verification
- 2FA with TOTP
- 2FA recovery codes
- 2FA with passkeys and security keys
- Password reset with 2FA
- Login throttling and rate limiting

Emails are just logged to the console. Rate limiting is implemented using JavaScript `Map`.

## Initialize project

Run Postgres db using docker-compose
```
docker-compose up
```

Install dependencies:

```
pnpm i
```

Run the Drizzle migrations to create the database schema
```
npx drizzle-kit migrate
```

Create a .env file. Generate a 128 bit (16 byte) string, base64 encode it, and set it as `ENCRYPTION_KEY`.

```bash
ENCRYPTION_KEY="L9pmqRJnO1ZJSQ2svbHuBA=="
```

> You can use OpenSSL to quickly generate a secure key.
>
> ```bash
> openssl rand --base64 16
> ```

Run the application:

```
pnpm dev
```

## Notes

- We do not consider user enumeration to be a real vulnerability so please don't open issues on it. If you really need to prevent it, just don't use emails.
- This example does not handle unexpected errors gracefully.
- There are some major code duplications (specifically for 2FA) to keep the codebase simple.
- TODO: Passkeys will only work when hosted on `localhost:5173`. Update the host and origin values before deploying.
- TODO: You may need to rewrite some queries and use transactions to avoid race conditions when using MySQL, Postgres, etc.
- TODO: This project relies on the `X-Forwarded-For` header for getting the client's IP address.
- TODO: Logging should be implemented.
