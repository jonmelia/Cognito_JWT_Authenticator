from jwt_authenticator import CognitoJWTAuthenticator

c.JupyterHub.authenticator_class = CognitoJWTAuthenticator
c.CognitoJWTAuthenticator.enable_kms_keys = False
c.CognitoJWTAuthenticator.enable_auth_state = True
c.CognitoJWTAuthenticator.region = 'eu-west-1'
c.CognitoJWTAuthenticator.user_pool_id = 'eu-west-1_example'
c.CognitoJWTAuthenticator.audience = 'example_client_id'
c.Authenticator.create_system_users = True
c.JupyterHub.log_level = 'DEBUG'