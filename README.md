This is an exploration into how to create an authentication system without using any auth providers or libraries.

# Authentication Overview

## Why JWT

This project uses JWTs for authentication. I chose this over simple sessions for scalability reasons. The key advantages are:
- It is stateless - you do not need to do a database lookup on every request, only when the access token expires
- It is easily used on distributed systems, as it is stateless

Neither of these advantages make a difference to this demo, but by learning how they work, I now know how I could implement this in a larger project.

The stateless nature of JWTs, however, does have a disadvantage - it is hard to invalidate a session. JWTs will work until they reach their expiry, and are not stored on the server. This means they cannot be invalidated, and you just have to wait until they expire. Refresh tokens are the solution to this.


## Access and Refresh Tokens

As mentioned before, the issue with JWTs is invalidation. A token is valid until it expires. There are several ways to get around this, including blacklisting tokens, but those are not stateless. The generally accepted method is to use two tokens - the access token, and the refresh token.

**Access token** - a token used to validate the user's session. If it is valid, the user can perform authenticated requests. This has a short life span (e.g. 5 minutes)
**Refresh token** - a token used to generate a new access token once the current one expires. This can be used without asking the user for their credentials again. Typically, this lasts a lot longer (e.g. 1 month). Using this, we can store a version number in the token and in the database to make invalidating the session easy.

With this method, if we want to invalidate the session, we can just increment the session version number in the database. Then when checking the refresh token, we can compare its version to the one in the database, and if they still match the user can stay logged in. Otherwise, they will be logged out, and have to enter credentials again to get a new access + refresh token.


## How it Works

The authentication flow works as follows:
1. The user enters credentials, which are sent to the server (`POST /session`)
2. If the credentials are valid, the server generates the access and refresh tokens
3. The two tokens are stored in HTTP only cookies by setting the `Set-Cookie` header in the HTTP response
4. On subsequent requests, `credentials: "include"` can be used to tell `fetch()` to include the cookies in the request headers
5. When a request is made to an authenticated endpoint, the server checks if the access token is valid (if it was signed with the correct key, has not expired, etc.). This does not require looking at the database
6. If it is not valid, the server will check the refresh token - if that is valid, it will generate a new access token and return that (checking the database again to make sure the session is still valid)

To invalidate a session, just increment the version number for that user's refresh token


## Why HTTP Only Cookies

HTTP only cookies are cookies that cannot be accessed through JavaScript - they can only be included in HTTP requests. This allows for better security than regular cookies or local/session storage, as malicious JavaScript cannot be used to steal the token(s). These will automatically be sent on any `fetch()` call with `credentials: "include"`


# Front-End

The front-end is a very simple login page, using typescript and SolidJS.


# Back-End

The back-end is written in Rust. I am using my own HTTP library that I built from scratch ([see here](https://github.com/jacob-horton/http-from-scratch)).

I am only using 3 other libraries:
- `jsonwebtoken` to encode/decode and validate JWTs
- `serde` + `serde_json` to serialise/deserialise JSON and JWT data
