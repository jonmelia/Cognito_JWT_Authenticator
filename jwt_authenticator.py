import jwt
import requests
import logging
import os
from logging.handlers import RotatingFileHandler
from jwt.algorithms import RSAAlgorithm
from jupyterhub.auth import Authenticator
from tornado.web import HTTPError
from traitlets import Unicode

# Setup logger
logger = logging.getLogger("CognitoJWTAuthenticator")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    log_file = os.environ.get("AUTH_LOG_FILE", "/var/log/jupyterhub/authenticator.log")

    # Rotating File Handler
    rotating_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    rotating_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    rotating_handler.setFormatter(file_formatter)
    logger.addHandler(rotating_handler)

    # Stream Handler (stdout for journald/systemd)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(file_formatter)
    logger.addHandler(stream_handler)

class CognitoJWTAuthenticator(Authenticator):
    region = Unicode(help="AWS region, e.g., eu-west-1").tag(config=True)
    user_pool_id = Unicode(help="Cognito User Pool ID").tag(config=True)
    audience = Unicode(help="Cognito App Client ID (audience)").tag(config=True)

    def get_jwks(self):
        jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        logger.debug(f"Fetching JWKS from {jwks_url}")
        try:
            resp = requests.get(jwks_url)
            resp.raise_for_status()
            return resp.json()["keys"]
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise HTTPError(500, "Could not retrieve Cognito public keys")

    def get_public_key(self, kid):
        keys = self.get_jwks()
        for key in keys:
            if key["kid"] == kid:
                logger.debug(f"Found matching key for kid: {kid}")
                return RSAAlgorithm.from_jwk(key)
        logger.warning(f"No matching key found for kid: {kid}")
        raise HTTPError(403, "Public key not found in JWKS")

    async def authenticate(self, handler, data=None):
        logger.info("Starting JWT authentication process")
        token = None

        auth_header = handler.request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            logger.debug("JWT found in Authorization header")

        if not token:
            token = handler.get_argument("token", default=None)
            if token:
                logger.debug("JWT found in POST body")

        if not token:
            token = handler.get_query_argument("token", default=None)
            if token:
                logger.debug("JWT found in URL query parameter")

        if not token:
            logger.warning("No JWT token found in request")
            raise HTTPError(403, "Missing JWT token")

        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header["kid"]
            logger.debug(f"Unverified token header: {unverified_header}")
            public_key = self.get_public_key(kid)
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}",
            )
            logger.info("JWT successfully verified")
            logger.debug(f"Decoded JWT claims: {decoded}")

            username = (
                decoded.get("cognito:username")
                or decoded.get("username")
                or decoded.get("email")
                or decoded.get("sub")
            )

            if not username:
                logger.error("JWT does not contain a valid username field")
                raise HTTPError(403, "Invalid token: username missing")

            logger.info(f"Authenticated user: {username}")
            return {"name": username}

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise HTTPError(403, "Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT validation error: {e}")
            raise HTTPError(403, f"Token validation failed: {str(e)}")
        except Exception as e:
            logger.exception(f"Unexpected error during JWT authentication: {e}")
            raise HTTPError(500, "Internal server error during authentication")