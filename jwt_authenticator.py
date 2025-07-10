import jwt
import requests
import logging
from jwt.algorithms import RSAAlgorithm
from jupyterhub.auth import Authenticator
from tornado.web import HTTPError
from traitlets import Unicode
from jupyterhub.handlers import BaseHandler


# Basic stdout logging
logger = logging.getLogger("CognitoJWTAuthenticator")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(stream_handler)

# Post-auth hook to redirect to /hub/spawn
def post_auth_redirect_hook(authenticator, handler: BaseHandler, auth_info):
    logger.debug("Post-auth hook triggered, redirecting to /hub/spawn")
    handler.redirect("/hub/spawn")

class CognitoJWTAuthenticator(Authenticator):
    region = Unicode(help="AWS region, e.g., eu-west-1").tag(config=True)
    user_pool_id = Unicode(help="Cognito User Pool ID").tag(config=True)
    audience = Unicode(help="Cognito App Client ID (audience)").tag(config=True)
    post_auth_hook = post_auth_redirect_hook  # Hook to force spawn form

    def get_jwks(self):
        jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        logger.debug(f"Fetching JWKS from {jwks_url}")
        try:
            resp = requests.get(jwks_url)
            resp.raise_for_status()
            return resp.json()["keys"]
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise HTTPError(500, f"Failed to fetch JWKS: {str(e)}")

    def get_public_key(self, kid):
        keys = self.get_jwks()
        for key in keys:
            if key["kid"] == kid:
                return RSAAlgorithm.from_jwk(key)
        raise HTTPError(403, "Public key not found in JWKS")

    async def authenticate(self, handler, data=None):
        logger.info("Starting JWT authentication process")
        token = None

        # Check headers
        auth_header = handler.request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

        # Check URL query parameter
        if not token:
            token = handler.get_query_argument("token", default=None)

        if not token:
            logger.warning("Missing JWT token")
            raise HTTPError(403, "Missing JWT token")

        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header["kid"]
            public_key = self.get_public_key(kid)
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}",
            )

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
            logger.warning(f"JWT validation failed: {e}")
            raise HTTPError(403, f"Token validation failed: {str(e)}")
        except Exception as e:
            logger.exception(f"Unexpected error during authentication: {e}")
            raise HTTPError(500, f"Unexpected error: {str(e)}")
