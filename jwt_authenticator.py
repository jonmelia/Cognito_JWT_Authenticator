import jwt
import requests
import logging
import tornado.web
from jwt.algorithms import RSAAlgorithm
from jupyterhub.auth import Authenticator
from tornado.web import HTTPError
from traitlets import Unicode
from jupyterhub.spawner import Spawner


# Set up stdout logger
logger = logging.getLogger("CognitoJWTAuthenticator")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)


class CognitoJWTAuthenticator(Authenticator):
    region = Unicode(help="AWS region, e.g., eu-west-1").tag(config=True)
    user_pool_id = Unicode(help="Cognito User Pool ID").tag(config=True)
    audience = Unicode(help="Cognito App Client ID (audience)").tag(config=True)

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
        keys = self.get_jwks()
        for key in keys:
            if key["kid"] == kid:
                return RSAAlgorithm.from_jwk(key)
        logger.error(f"No matching public key found for kid: {kid}")
        raise HTTPError(403, "Public key not found")

    async def authenticate(self, handler, data=None):
        logger.info("Starting Cognito JWT authentication")
        token = None

        # Get token from Authorization header
        auth_header = handler.request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

        # Or from query parameter
        if not token:
            token = handler.get_query_argument("token", default=None)

        if not token:
            logger.warning("Missing JWT token")
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
                logger.error("JWT missing valid username claim")
                raise HTTPError(403, "Invalid token: username missing")

            logger.info(f"Authenticated user: {username}")
            return {"name": username}

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            raise HTTPError(403, "Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT invalid: {e}")
            raise HTTPError(403, f"Invalid token: {str(e)}")
        except Exception as e:
            logger.exception("Unexpected authentication error")
            raise HTTPError(500, "Unexpected authentication error")

    async def pre_spawn_start(self, user, spawner: Spawner):
        logger.info(f"[pre_spawn_start] User: {user.name}, Spawner: {spawner.name}")
        logger.debug(f"[pre_spawn_start] user_options: {spawner.user_options}")
        logger.debug(f"[pre_spawn_start] spawner.server: {spawner.server}")

        profile_selected = spawner.user_options.get("profile_form")
        if not spawner.server and not profile_selected:
            logger.warning(f"[pre_spawn_start] Auto-spawn attempt blocked for {user.name}")
            raise Exception("Spawn blocked: user must select a profile manually.")
