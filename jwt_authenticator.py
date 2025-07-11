import jwt
import requests
import logging
import tornado.web
import base64
from jwt.algorithms import RSAAlgorithm
from jupyterhub.auth import Authenticator
from tornado.web import HTTPError
from traitlets import Unicode, Bool
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
    enable_kms_keys = Bool(False, help="Enable KMS key and bucket handling in authentication (optional, can be disabled)" ).tag(config=True)  # Set to False to completely disable KMS/bucket injection

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

    def decode_input(self, input_value):
        if not input_value:
            return None
        try:
            decoded = base64.urlsafe_b64decode(input_value.encode()).decode()
            logger.debug("Successfully base64-decoded input")
            return decoded
        except Exception:
            logger.debug("Input is not base64-encoded; using raw input")
            return input_value

    async def authenticate(self, handler, data=None):
        logger.info("Starting Cognito JWT authentication")

        token_input = handler.get_argument("token", default=None)

        user_kms = shared_kms = bucket = None
        # KMS and bucket values will only be retrieved and processed if enabled
        if self.enable_kms_keys:
            # These lines can be removed if KMS and bucket are not required
            user_kms_input = handler.get_argument("user_kms_key", default=None)
            shared_kms_input = handler.get_argument("shared_kms_key", default=None)
            bucket_input = handler.get_argument("bucket", default=None)
            user_kms = self.decode_input(user_kms_input)
            shared_kms = self.decode_input(shared_kms_input)
            bucket = self.decode_input(bucket_input)

        if not token_input:
            logger.warning("Missing JWT token")
            raise HTTPError(403, "Missing token")

        token = self.decode_input(token_input)

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

            # Optionally include auth_state only when KMS/bucket handling is enabled
            if self.enable_kms_keys:
                # This entire block can be removed if KMS/bucket support is unnecessary
                auth_state = {}
                if user_kms:
                    auth_state["user_kms_key"] = user_kms
                if shared_kms:
                    auth_state["shared_kms_key"] = shared_kms
                if bucket:
                    auth_state["bucket"] = bucket
                return {"name": username, "auth_state": auth_state or None}
            else:
                return {"name": username}

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            raise HTTPError(403, "Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT invalid: {e}")
            raise HTTPError(403, f"Invalid token: {str(e)}")
        except Exception as e:
            logger.exception("Unexpected authentication error")
            raise HTTPError(500, f"Unexpected error during authentication: {str(e)}")

    async def pre_spawn_start(self, user, spawner: Spawner):
        logger.info(f"[pre_spawn_start] User: {user.name}, Spawner: {spawner.name}")
        logger.debug(f"[pre_spawn_start] user_options: {spawner.user_options}")
        logger.debug(f"[pre_spawn_start] spawner.server: {spawner.server}")

        profile_form_flag = spawner.user_options.get("profile_form", None)

        if not spawner.server and not profile_form_flag:
            logger.warning(f"[pre_spawn_start] Blocking auto-spawn for {user.name} (no profile_form marker)")
            handler = spawner.handler
            if handler:
                handler.redirect('/hub/spawn')
                return
            raise HTTPError(403, "Auto-spawn blocked: user must manually select a profile.")

async def pre_spawn_hook(spawner):
    authenticator = spawner.authenticator
    # Only apply KMS/bucket S3 mounting logic if enabled. Remove this block if not needed.
    if getattr(authenticator, 'enable_kms_keys', False):
        auth_state = await spawner.user.get_auth_state()
        user_kms = auth_state.get("user_kms_key") if auth_state else None
        shared_kms = auth_state.get("shared_kms_key") if auth_state else None
        bucket = auth_state.get("bucket") if auth_state else "your-bucket"
        username = spawner.user.name

        if user_kms:
            spawner.environment.setdefault("S3_USER_MOUNT_ENABLED", "true")
            spawner.environment.setdefault("S3_USER_BUCKET_PATH", f"s3://{bucket}/users/{username}/")
            spawner.environment.setdefault("S3_USER_KMS_KEY_ID", user_kms)
            spawner.environment.setdefault("S3_USER_MOUNT_PATH", "/home/jovyan")

        if shared_kms:
            spawner.environment.setdefault("S3_SHARED_MOUNT_ENABLED", "true")
            spawner.environment.setdefault("S3_SHARED_BUCKET_PATH", f"s3://{bucket}/shared/{username}/")
            spawner.environment.setdefault("S3_SHARED_KMS_KEY_ID", shared_kms)
            spawner.environment.setdefault("S3_SHARED_MOUNT_PATH", "/mnt/shared")

