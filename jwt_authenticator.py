from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from tornado.web import HTTPError, RequestHandler, Finish
from traitlets import Unicode
import jwt
import requests
import logging
from jwt.algorithms import RSAAlgorithm


logger = logging.getLogger("CognitoJWTAuthenticator")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(stream_handler)


class CognitoJWTAuthenticator(Authenticator):
    region = Unicode(help="AWS region, e.g., eu-west-1").tag(config=True)
    user_pool_id = Unicode(help="Cognito User Pool ID").tag(config=True)
    audience = Unicode(help="Cognito App Client ID").tag(config=True)

    async def authenticate(self, handler, data=None):
        logger.info("Starting JWT authentication process")
        token = None

        auth_header = handler.request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

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
                logger.error("JWT missing username field")
                raise HTTPError(403, "Token missing username")

            logger.info(f"Authenticated user: {username}")
            return {"name": username}

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise HTTPError(403, "Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise HTTPError(403, "Invalid token")
        except Exception as e:
            logger.exception("Unexpected error")
            raise HTTPError(500, "Unexpected error")

    def get_jwks(self):
        url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        try:
            logger.debug(f"Fetching JWKS from {url}")
            resp = requests.get(url)
            resp.raise_for_status()
            return resp.json()["keys"]
        except Exception as e:
            logger.exception("Failed to fetch JWKS")
            raise HTTPError(500, "Failed to fetch JWKS")

    def get_public_key(self, kid):
        keys = self.get_jwks()
        for key in keys:
            if key["kid"] == kid:
                return RSAAlgorithm.from_jwk(key)
        logger.error(f"No matching public key for kid: {kid}")
        raise HTTPError(403, "Public key not found")

