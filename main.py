import base64
import hashlib
import logging
import os
import secrets
import time
from typing import Any, TypedDict
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from joserfc import jwt
from joserfc.jwk import OctKey
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

"""
Environment
"""


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


SESSION_SECRET_KEY = get_required_env("SESSION_SECRET_KEY")  # Secret key for session middleware
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "scoutid-oidc-server")  # Name of the session cookie
LOGIN_TIMEOUT = int(os.getenv("LOGIN_TIMEOUT", 300))  # Timeout for login in seconds

JWT_EXP_DELTA_SECONDS = int(os.getenv("JWT_EXP_DELTA_SECONDS", 3600))  # Expiration time for JWT in seconds
IDP_ISSUER = os.getenv("IDP_ISSUER", "http://localhost:5000")  # Issuer for the OIDC provider (external, browser-facing)
IDP_INTERNAL_URL = os.getenv("IDP_INTERNAL_URL", IDP_ISSUER)  # Internal cluster URL for server-to-server endpoints

IDP_CLIENT_ID = get_required_env("IDP_CLIENT_ID")  # Client ID for the OIDC provider
IDP_CLIENT_SECRET = get_required_env("IDP_CLIENT_SECRET")  # Client secret for the OIDC provider
IDP_REDIRECT_URI = get_required_env("IDP_REDIRECT_URI")  # Redirect URI for the OIDC provider
IDP_POST_LOGOUT_REDIRECT_URI = os.getenv("IDP_POST_LOGOUT_REDIRECT_URI")  # Allowed post-logout redirect URI

FORGOT_PASSWORD_URL = os.getenv("FORGOT_PASSWORD_URL", "https://www.scoutnet.se/request_password")  # Forgot password link shown on login page (set empty to hide)

SCOUTNET_API = os.getenv("SCOUTNET_API", "https://scoutnet.se/api")  # Base URL for the Scoutnet API
SCOUTNET_APP_ID = os.getenv("SCOUTNET_APP_ID", "change_me")  # Identifies the app (> 10 chars)
SCOUTNET_APP_NAME = os.getenv("SCOUTNET_APP_NAME", "scoutid-oidc-provider")  # Name of the app
SCOUTNET_APP_DEVICE_NAME = os.getenv("SCOUTNET_APP_DEVICE_NAME", "My ScoutID")  # Name of the "device"

DEBUG_MODE = os.getenv("DEBUG", "false") == "true"  # Global DEBUG logging
LOGFORMAT = "%(asctime)s %(funcName)-10s [%(levelname)s] %(message)s"  # Log format
HTTP_SERVER_PORT = int(os.getenv("HTTP_SERVER_PORT", "5000"))


"""
Global variables
"""
UserInfo = dict[str, Any]


class ActiveRequest(TypedDict):
    redirect_uri: str
    scope: str
    state: str | None
    session_state: str
    nonce: str | None
    timestamp: int
    userinfo: UserInfo | None


class AccessTokenData(TypedDict):
    userinfo: UserInfo
    exp: int


active_requests: dict[str, ActiveRequest] = {}  # Dictionary to store request codes
access_tokens: dict[str, AccessTokenData] = {}  # Dictionary to store access_token -> {userinfo, exp}
failed_login_attempts: dict[str, tuple[int, int]] = {}  # IP -> (count, last_attempt_timestamp)
MAX_ACTIVE_REQUESTS = 1000
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_SECONDS = 300
MAX_PARAM_LENGTH = 512
MAX_CREDENTIAL_LENGTH = 256
SCOUTNET_API_TIMEOUT = 10.0
REMEMBER_ME_MAX_AGE = 30 * 24 * 3600  # 30 days


def cleanup_expired_requests():
    """Remove expired entries from active_requests, access_tokens, and failed_login_attempts."""
    now = int(time.time())
    expired = [code for code, data in active_requests.items() if now - data["timestamp"] > LOGIN_TIMEOUT]
    for code in expired:
        del active_requests[code]
    expired_tokens = [token for token, data in access_tokens.items() if now > data["exp"]]
    for token in expired_tokens:
        del access_tokens[token]
    expired_ips = [ip for ip, (_, ts) in failed_login_attempts.items() if now - ts > LOGIN_BLOCK_SECONDS]
    for ip in expired_ips:
        del failed_login_attempts[ip]


def is_allowed_post_logout_redirect(target_url: str, allowed_base_url: str | None) -> bool:
    if not allowed_base_url:
        return True

    allowed = urlparse(allowed_base_url)
    target = urlparse(target_url)
    if (target.scheme, target.netloc) != (allowed.scheme, allowed.netloc):
        return False

    allowed_path = allowed.path.rstrip("/")
    if not allowed_path:
        return True  # allowed base is origin-only, any path is permitted
    target_path = target.path.rstrip("/") or "/"
    return target_path == allowed_path or target_path.startswith(f"{allowed_path}/")


"""
JWT setup
"""
jwt_key = OctKey.import_key(IDP_CLIENT_SECRET.encode())  # HS256: client secret = signing key


"""
Jinja2 setup
"""
templates = Jinja2Templates(directory="templates")


"""
FastAPI setup and middleware
"""
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie=SESSION_COOKIE_NAME,
    max_age=None,  # Session cookie by default; RememberMeMiddleware extends when needed
    same_site="lax",
    https_only=not DEBUG_MODE,
)
_parsed_redirect = urlparse(IDP_REDIRECT_URI) if IDP_REDIRECT_URI else None
_cors_origin = f"{_parsed_redirect.scheme}://{_parsed_redirect.netloc}" if _parsed_redirect else ""
app.add_middleware(
    CORSMiddleware,
    allow_origins=[_cors_origin] if _cors_origin else [],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")


class RememberMeMiddleware:
    """Adds Max-Age to session cookie when remember_me is set in the session.

    When added after SessionMiddleware, this wraps around it (outermost).
    On response, it checks scope["session"] for the remember_me flag and
    appends Max-Age to the session cookie header if set.
    Without remember_me, the cookie remains a session cookie (no Max-Age).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                session = scope.get("session", {})
                if session.get("remember_me"):
                    headers = message.get("headers", [])
                    new_headers = []
                    cookie_name = SESSION_COOKIE_NAME.encode()
                    for name, value in headers:
                        if name == b"set-cookie" and cookie_name in value:
                            value += f"; Max-Age={REMEMBER_ME_MAX_AGE}".encode()
                        new_headers.append((name, value))
                    message["headers"] = new_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


app.add_middleware(RememberMeMiddleware)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        if not DEBUG_MODE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)


"""
FastAPI custom 404 handler
"""


@app.exception_handler(404)
async def custom_404_handler(request, exc):
    """
    404 error handler to return an NGINX-lookalike HTML page.
    """
    html_content = """<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=404)


"""
Authentication routes (called from client)
"""


@app.get("/auth/authorize", include_in_schema=False)
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str | None,
    nonce: str | None,
):
    """
    Called from the client, either direct or through a redirect from the client
    If the user has an active session, redirect back to caller with an authorization code.
    If the user doesn't have an active session, redirect to a login page.
    """

    logging.info("Authorization request received")
    cleanup_expired_requests()

    if len(active_requests) >= MAX_ACTIVE_REQUESTS:
        logging.error("Too many active authorization requests")
        raise HTTPException(status_code=429, detail="Too many requests")

    if any(len(p or "") > MAX_PARAM_LENGTH for p in [state, nonce, scope]):
        logging.error("Parameter exceeds maximum length")
        raise HTTPException(status_code=400, detail="Parameter too long")

    if response_type != "code":
        logging.error(f"Unsupported response type: {response_type}")
        raise HTTPException(status_code=400, detail="Unsupported response type")
    if client_id != IDP_CLIENT_ID:
        logging.error(f"Invalid client ID: {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client ID")
    if "openid" not in scope:
        logging.error("Missing 'openid' in scope")
        raise HTTPException(status_code=400, detail="Missing 'openid' in scope")
    if state is None:
        logging.error("Missing state parameter")
        raise HTTPException(status_code=400, detail="Missing state parameter")
    if redirect_uri != IDP_REDIRECT_URI:
        logging.error(f"Invalid redirect URI: {redirect_uri}")
        raise HTTPException(status_code=400, detail="Invalid redirect URI")

    # Generate session_state according to the OpenID Connect session spec.
    origin_url = redirect_uri.split("?")[0]
    salt = secrets.token_urlsafe(16)
    session_state_raw = f"{client_id} {origin_url} {state} {salt}"
    session_state_hash = hashlib.sha256(session_state_raw.encode()).digest()
    session_state = f"{base64.urlsafe_b64encode(session_state_hash).decode().rstrip('=')}.{salt}"

    code = secrets.token_urlsafe(32)  # Generate a secure 32 byte unique authorization code

    active_requests[code] = {
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "session_state": session_state,
        "nonce": nonce,
        "timestamp": int(time.time()),  # Store the timestamp for expiration checks
        "userinfo": None,
    }

    userinfo = request.session.get("userinfo")  # Check for an active user session
    if userinfo is None:  # No session found
        logging.info("No active session found, redirecting to login page")
        request.session["auth_code"] = code  # Save the auth_code in the session
        return RedirectResponse("/auth/login")  # Redirect to the login page

    active_requests[code]["userinfo"] = userinfo  # Save userinfo for expected token request from client
    logging.info("Active session found, redirecting back to client")

    redirect_response = f"{redirect_uri}?state={state}&session_state={session_state}&code={code}"
    return RedirectResponse(redirect_response)  # Return to client


@app.get("/auth/login", include_in_schema=False)
async def login_page(request: Request):
    """
    Login page for user authentication.
    """
    csrf_token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = csrf_token
    return templates.TemplateResponse(
        request=request, name="login.html", context={"login_failed": False, "csrf_token": csrf_token, "forgot_password_url": FORGOT_PASSWORD_URL}
    )


@app.post("/auth/login", include_in_schema=False)
async def login_token(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False),
    csrf_token: str = Form(...),
):
    """
    The user doesn't have an active session, so we need to log in the user.
    The user has entered their credentials in the login form.
    We need to validate the credentials against the Scoutnet API.
    If the credentials are valid, we create a session and redirect back to client with the authorization code.
    If the credentials are invalid, we return an error message.
    """

    logging.info("Login post received")

    client_ip = request.client.host if request.client else "unknown"
    now = int(time.time())
    if client_ip in failed_login_attempts:
        attempts, last_ts = failed_login_attempts[client_ip]
        if now - last_ts < LOGIN_BLOCK_SECONDS and attempts >= MAX_LOGIN_ATTEMPTS:
            logging.warning(f"SECURITY: Rate limited login from {client_ip}")
            raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")

    session_csrf = request.session.pop("csrf_token", None)
    if not session_csrf or not secrets.compare_digest(session_csrf, csrf_token):
        logging.error("SECURITY: CSRF token mismatch")
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    if len(username) > MAX_CREDENTIAL_LENGTH or len(password) > MAX_CREDENTIAL_LENGTH:
        raise HTTPException(status_code=400, detail="Credentials too long")

    code = request.session.get("auth_code")
    if not code or code not in active_requests:
        logging.error("No or wrong authorization code found in session")
        raise HTTPException(status_code=400, detail="No or wrong authorization code found in session")
    if int(time.time()) - active_requests[code]["timestamp"] > LOGIN_TIMEOUT:
        del active_requests[code]  # Remove expired request
        del request.session["auth_code"]  # Remove auth_code from session
        logging.error("Authorization code expired")
        raise HTTPException(status_code=400, detail="Login timed out")

    async with httpx.AsyncClient(timeout=SCOUTNET_API_TIMEOUT) as client:
        auth = {
            "username": username,
            "password": password,
            "app_id": SCOUTNET_APP_ID,
            "app_name": SCOUTNET_APP_NAME,
            "device_name": SCOUTNET_APP_DEVICE_NAME,
        }
        response = await client.get(f"{SCOUTNET_API}/authenticate", params=auth)
        if response.status_code == 200:
            data = response.json()
            token = data["token"]
        else:
            logging.info(f"SECURITY: Failed login for '{username}' from {client_ip}")
            prev_attempts = failed_login_attempts.get(client_ip, (0, 0))[0]
            failed_login_attempts[client_ip] = (prev_attempts + 1, now)
            new_csrf = secrets.token_urlsafe(32)
            request.session["csrf_token"] = new_csrf
            return templates.TemplateResponse(
                request=request, name="login.html", context={"login_failed": True, "csrf_token": new_csrf, "forgot_password_url": FORGOT_PASSWORD_URL}
            )

        auth_header = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = await client.get(f"{SCOUTNET_API}/get/profile", headers=auth_header)
        response.raise_for_status()  # Unknown error
        profile = response.json()
        response = await client.get(f"{SCOUTNET_API}/get/user_roles", headers=auth_header)
        response.raise_for_status()  # Unknown error
        user_roles = response.json()
        role_list = [f"{a}:{c}:member" for a, b in profile["memberships"].items() if b for c in b]
        role_list.extend([f"{a}:{c}:{e}" for a, b in user_roles.items() if b for c, d in b.items() for e in d.values()])

        userinfo: UserInfo = {
            "sub": profile["member_no"],
            "name": profile["first_name"] + " " + profile["last_name"],
            "given_name": profile["first_name"],
            "family_name": profile["last_name"],
            "preferred_username": profile["username"] + "@scoutnet.se",
            "email": profile["email"],
            "email_verified": True,
            "locale": profile["language"],
            "roles": role_list,
        }
        logging.debug(f"Authenticated user sub={userinfo['sub']}, roles={len(role_list)}")
        logging.info(f"User {userinfo['sub']} logged in successfully from {client_ip}")
        failed_login_attempts.pop(client_ip, None)

    request.session["userinfo"] = userinfo  # Save userinfo in session
    if remember_me:
        request.session["remember_me"] = True
    active_requests[code]["userinfo"] = userinfo  # And locally
    del request.session["auth_code"]  # Remove auth_code from session

    redirect_uri = active_requests[code]["redirect_uri"]
    state = active_requests[code]["state"]
    session_state = active_requests[code]["session_state"]
    redirect_response = f"{redirect_uri}?state={state}&session_state={session_state}&code={code}"

    return RedirectResponse(url=redirect_response, status_code=303)  # Use 303 See Other to force a GET


@app.get("/auth/logout", include_in_schema=False)
def logout(request: Request, id_token_hint: str, post_logout_redirect_uri: str, state: str | None = None):
    """
    Logout the user by removing the session and redirecting to the post_logout_redirect_uri.
    Verifies the id_token_hint JWT signature and checks that the subject matches the session.
    state is optional per OpenID Connect RP-Initiated Logout 1.0 spec.
    """
    logging.info("Logout request received")

    # Allow any URI that starts with the configured base (e.g. the wiki may redirect
    # back to the page the user was on, not always the exact root URL).
    if not is_allowed_post_logout_redirect(post_logout_redirect_uri, IDP_POST_LOGOUT_REDIRECT_URI):
        logging.error("Invalid post_logout_redirect_uri")
        raise HTTPException(status_code=400, detail="Invalid post_logout_redirect_uri")

    try:
        token = jwt.decode(id_token_hint, jwt_key)
        userinfo = token.claims
    except Exception:
        logging.error("Invalid id_token_hint signature")
        raise HTTPException(status_code=400, detail="Invalid id_token_hint")

    userinfo_session = request.session.get("userinfo")
    if userinfo_session is None:
        logging.error("No active session found")
        raise HTTPException(status_code=400, detail="No active session found")
    if str(userinfo_session["sub"]) != str(userinfo.get("sub")):
        logging.error("Userinfo does not match session")
        raise HTTPException(status_code=400, detail="Userinfo does not match session")

    request.session.clear()

    logging.info(f"User {userinfo['sub']} logged out successfully")
    redirect_response = f"{post_logout_redirect_uri}?state={state}" if state else post_logout_redirect_uri
    return RedirectResponse(redirect_response)


"""
Token API (called from relying party)
"""


@app.post("/api/token", include_in_schema=False)
async def issue_token(
    grant_type: str = Form(...),
    redirect_uri: str | None = Form(None),
    code: str | None = Form(None),
    authorization: str | None = Header(None),  # Capture the Authorization header
):
    """
    Called from client to exchange the authorization code for an access token.
    The request is sent as a POST request with the following parameters:
    - grant_type: The type of grant being requested. Should be "authorization_code".
    - redirect_uri: The redirect URI used in the authorization request.
    - code: The authorization code received in the redirect from the authorization endpoint.
    - authorization: The Authorization header containing the client credentials.
    """

    logging.info("Token request received")
    logging.debug("Token request with authorization header present=%s", authorization is not None)

    if not authorization or not authorization.startswith("Basic "):
        logging.error("Invalid or missing Authorization header")
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")
    try:
        auth_decoded = base64.b64decode(authorization.split(" ")[1]).decode("utf-8")
        client_id, client_secret = auth_decoded.split(":", 1)
    except Exception:
        logging.error("Invalid Authorization header format")
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    if client_id != IDP_CLIENT_ID or client_secret != IDP_CLIENT_SECRET:
        logging.error("Invalid client credentials")
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    if grant_type != "authorization_code":
        logging.error(f"Unsupported grant_type: {grant_type}")
        raise HTTPException(status_code=400, detail="unsupported_grant_type")
    if not code:
        logging.error("Missing code")
        raise HTTPException(status_code=400, detail="invalid_request")
    if redirect_uri != IDP_REDIRECT_URI:
        logging.error(f"Invalid redirect_uri: {redirect_uri}")
        raise HTTPException(status_code=400, detail="invalid_grant")
    if code not in active_requests:
        logging.error("Invalid or already-used authorization code")
        raise HTTPException(status_code=400, detail="invalid_grant")

    if int(time.time()) - active_requests[code]["timestamp"] > LOGIN_TIMEOUT:
        del active_requests[code]
        logging.error("Authorization code expired")
        raise HTTPException(status_code=400, detail="Authorization code expired")

    request_details = active_requests.pop(code)
    request_userinfo = request_details["userinfo"]
    if request_userinfo is None:
        logging.error("Authorization code is missing associated userinfo")
        raise HTTPException(status_code=400, detail="invalid_grant")

    scope = request_details["scope"]
    session_state = request_details["session_state"]
    nonce = request_details["nonce"]
    timestamp = request_details["timestamp"]

    access_token = secrets.token_urlsafe(32)

    id_token_payload: dict[str, Any] = {
        "iss": IDP_ISSUER,  # Should be a URL, e.g., "https://your-idp.example.com"
        "sub": request_userinfo["sub"],
        "aud": client_id,
        "exp": int(time.time()) + JWT_EXP_DELTA_SECONDS,
        "iat": int(time.time()),
        "auth_time": timestamp,
        "azp": client_id,
        "sid": session_state,
    }
    # Add nonce if present
    if nonce:
        id_token_payload["nonce"] = nonce
    # Add standard OIDC claims if available
    for claim in ["name", "email", "email_verified", "preferred_username", "given_name", "family_name", "locale"]:
        if claim in request_userinfo:
            id_token_payload[claim] = request_userinfo[claim]
    # Add roles if present
    if "roles" in request_userinfo:
        id_token_payload["roles"] = request_userinfo["roles"]

    id_token = jwt.encode(
        {"alg": "HS256", "typ": "JWT"},
        id_token_payload,
        jwt_key,
    )

    exp = int(time.time()) + JWT_EXP_DELTA_SECONDS
    access_tokens[access_token] = {
        "userinfo": request_userinfo,
        "exp": exp,
    }

    token = {
        "access_token": access_token,
        "expires_in": JWT_EXP_DELTA_SECONDS,
        "token_type": "Bearer",
        "id_token": id_token,
        "not-before-policy": 0,
        "session_state": session_state,
        "scope": scope,
        "expires_at": exp,
    }

    return token


@app.get("/api/userinfo", include_in_schema=False)
async def userinfo(authorization: str | None = Header(None)):
    """
    Returns claims for the authenticated user identified by the Bearer access token.
    Called server-side by the OIDC client (e.g. jumbojett) after token exchange.
    """
    logging.info("Userinfo request received")
    if not authorization or not authorization.startswith("Bearer "):
        logging.error("Missing or invalid Authorization header for userinfo")
        raise HTTPException(status_code=401, detail="invalid_token")

    token = authorization.split(" ", 1)[1]
    token_data = access_tokens.get(token)
    if not token_data:
        logging.error("Unknown or expired access token for userinfo")
        raise HTTPException(status_code=401, detail="invalid_token")
    if int(time.time()) > token_data["exp"]:
        del access_tokens[token]
        logging.error("Expired access token for userinfo")
        raise HTTPException(status_code=401, detail="invalid_token")

    claims = dict(token_data["userinfo"])
    claims["iss"] = IDP_ISSUER
    return claims


"""
OIDC Discovery
"""


@app.get("/.well-known/openid-configuration", include_in_schema=False)
async def openid_configuration():
    return {
        "issuer": IDP_ISSUER,
        "authorization_endpoint": f"{IDP_ISSUER}/auth/authorize",  # browser-facing (via ingress)
        "token_endpoint": f"{IDP_INTERNAL_URL}/api/token",  # server-to-server (cluster-internal)
        "userinfo_endpoint": f"{IDP_INTERNAL_URL}/api/userinfo",  # server-to-server (cluster-internal)
        "end_session_endpoint": f"{IDP_ISSUER}/auth/logout",  # browser-facing (via ingress)
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_supported": [
            "sub",
            "name",
            "email",
            "email_verified",
            "preferred_username",
            "given_name",
            "family_name",
            "locale",
            "roles",
        ],
    }


@app.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks():
    return {"keys": []}


"""
Main function (entry point)
"""
if __name__ == "__main__":
    # Enable logging. INFO is default. DEBUG if requested
    logging.basicConfig(level=logging.DEBUG if DEBUG_MODE else logging.INFO, format=LOGFORMAT)
    logging.getLogger("multipart").setLevel(logging.WARNING) # Supress noisy python-multipart parser

    uvicorn.run("main:app", host="0.0.0.0", port=HTTP_SERVER_PORT, log_config=None)
