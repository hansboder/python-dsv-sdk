import os
import pytest
from dotenv import load_dotenv
from thycotic.secrets.vault import AWSGrantAuthorizer, PasswordGrantAuthorizer, SecretsVault


load_dotenv()


@pytest.fixture
def env_vars():
    return {
        "client_id": os.getenv("DSV_CLIENT_ID"),
        "client_secret": os.getenv("DSV_CLIENT_SECRET"),
        "access_key": os.getenv("AWS_ACCESS_KEY_ID"),
        "secret_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "session_token": os.getenv("AWS_SESSION_TOKEN"),
        "aws_region": os.getenv("AWS_DEFAULT_REGION"),
        "base_url": os.getenv("DSV_BASE_URL"),

    }

@pytest.fixture
def authorizer(env_vars):
    return PasswordGrantAuthorizer(
        env_vars["base_url"],
        env_vars["client_id"],
        env_vars["client_secret"],
    )

@pytest.fixture
def aws_authorizer(env_vars):
    return AWSGrantAuthorizer(
        env_vars["base_url"],
        region=env_vars["aws_region"],
        access_key=env_vars["access_key"],
        secret_key=env_vars["secret_key"],
        session_token=env_vars["session_token"]
    )

@pytest.fixture
def aws_implicit_authorizer(env_vars):
    return AWSGrantAuthorizer(
        env_vars["base_url"],
    )

@pytest.fixture()
def vault(authorizer, env_vars):
    return SecretsVault(env_vars["base_url"], authorizer)
