import unittest
from unittest.mock import patch, MagicMock
from tornado.web import RequestHandler
from cognito_jupyterhub_auth.jwt_authenticator import CognitoJWTAuthenticator


class DummyHandler:
    def __init__(self, headers=None, arguments=None, query_arguments=None):
        self.request = MagicMock()
        self.request.headers = headers or {}
        self.arguments = arguments or {}
        self.query_arguments = query_arguments or {}

    def get_argument(self, name, default=None):
        return self.arguments.get(name, [default])[0]

    def get_query_argument(self, name, default=None):
        return self.query_arguments.get(name, [default])[0]


class CognitoJWTAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        self.authenticator = CognitoJWTAuthenticator()
        self.authenticator.region = 'eu-west-1'
        self.authenticator.user_pool_id = 'eu-west-1_example'
        self.authenticator.audience = 'example_client_id'

    @patch('cognito_jupyterhub_auth.jwt_authenticator.requests.get')
    def test_get_jwks_success(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'keys': [{'kid': '1234'}]}
        keys = self.authenticator.get_jwks()
        self.assertEqual(keys[0]['kid'], '1234')

    @patch('cognito_jupyterhub_auth.jwt_authenticator.requests.get')
    def test_get_jwks_failure(self, mock_get):
        mock_get.side_effect = Exception("Failed")
        with self.assertRaises(Exception):
            self.authenticator.get_jwks()

    def test_handler_argument_methods(self):
        handler = DummyHandler(
            headers={'Authorization': 'Bearer dummy'},
            arguments={'token': ['formtoken']},
            query_arguments={'token': ['querytoken']}
        )
        self.assertEqual(handler.get_argument("token"), 'formtoken')
        self.assertEqual(handler.get_query_argument("token"), 'querytoken')


if __name__ == '__main__':
    unittest.main()