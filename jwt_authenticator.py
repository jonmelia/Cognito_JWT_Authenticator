import jwt
import requests
import logging
import tornado.web
from jwt.algorithms import RSAAlgorithm
from jupyterhub.auth import Authenticator
from tornado.web import HTTPError
from traitlets import Unicode
from jupyterhub.spawner import Spawner

# Setup logging to stdout
logger = logging.getLogger("CognitoJWTAuthenticator")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

class CognitoJWTAuthenticator(Authenticator):
    region = Unicode(help="AWS region, e.g., eu-west-1").tag(config=True)
    user_pool_id = Unicode(help="Cognito User Pool ID").tag(config=True)
    audience = Unicode(help="Cognito App Client ID").tag(config=True)

    def get_jwks(self):
        url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        logger.debug(f"Fetching JWKS from {url}")
        try:
            resp = requests.get(url)
            resp.raise_for_status()
            return resp.json()["keys"]
        except Exception as e:
            logger.exception("Failed to fetch JWKS")
            raise HTTPError(500, "Failed to fetch Cognito JWKS")

    def get_public_key(self, kid):
        for key in self.get_jwks():
            if key["kid"] == kid:
                return RSAAlgorithm.from_jwk(key)
        logger.error("Matching public key not found for kid: %s", kid)
        raise HTTPError(403, "Public key not found in JWKS")

    async def authenticate(self, handler, data=None):
        logger.info("Starting Cognito JWT authentication")
        token = None

        # Header check
        auth_header = handler.request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

        # URL query parameter
        if not token:
            token = handler.get_query_argument("token", default=None)

        if not token:
            logger.warning("No JWT token provided")
            raise HTTPError(403, "Missing token")

        try:
            unverified = jwt.get_unverified_header(token)
            kid = unverified["kid"]
            public_key = self.get_public_key(kid)
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"
            )
            logger.debug("Decoded JWT: %s", decoded)

            username = (
                decoded.get("cognito:username")
                or decoded.get("username")
                or decoded.get("email")
                or decoded.get("sub")
            )

            if not username:
                logger.error("JWT missing a valid username claim")
                raise HTTPError(403, "No username in token")

            logger.info(f"Authenticated Cognito user: {username}")
            return {"name": username}

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise HTTPError(403, "Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning("JWT token invalid: %s", e)
            raise HTTPError(403, f"Invalid token: {str(e)}")
        except Exception as e:
            logger.exception("Unexpected error during JWT authentication")
            raise HTTPError(500, "Unexpected authentication error")

    async def pre_spawn_start(self, user, spawner: Spawner):
        logger.info(f"[pre_spawn_start] user: {user.name}, spawner: {spawner.name}")
        if not getattr(spawner, 'profile', None):
            logger.info(f"[pre_spawn_start] No profile selected. Blocking auto-spawn for user: {user.name}")
            raise Exception("Spawn blocked to force user to select profile")
