
from setuptools import setup

setup(
    name="cognito-jupyterhub-auth",
    version="0.1.0",
    description="JWT-based JupyterHub authenticator for AWS Cognito",
    author="Your Name",
    author_email="your.email@example.com",
    py_modules=["jwt_authenticator"],
    install_requires=[
        "jupyterhub",
        "pyjwt",
        "requests"
    ],
    classifiers=[
        "Framework :: Jupyter",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
