# Cognito JWT Authenticator for JupyterHub

This project provides a custom JWT authenticator for JupyterHub using AWS Cognito.

## Features

- Accepts JWT via query param, header, or POST.
- Validates against AWS Cognito public JWKS.
- Optional Flask tool to obtain token via hosted UI.

## Usage

1. Update `jupyterhub_config.py` with your region, user pool ID, and client ID.
2. Run JupyterHub with this config.
3. Login via:

```
http://<your-jupyterhub-host>/hub/login?token=<your-cognito-id-token>
```

Or POST using curl:

```
curl -X POST http://localhost:8000/hub/login -d "token=eyJ..."
```

## Optional: Test with Flask Token Grabber

```bash
python flask_token_grabber.py
```

Login with Cognito and copy your `id_token` from the page.