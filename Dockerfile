FROM python:3.10-slim
RUN apt-get update && apt-get install -y nodejs npm
RUN pip install jupyterhub notebook pyjwt requests flask
COPY . /srv/jupyterhub
WORKDIR /srv/jupyterhub
CMD ["jupyterhub", "-f", "jupyterhub_config.py"]