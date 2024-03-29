# The Thycotic DevOps Secrets Vault Python SDK

![PyPI Version](https://img.shields.io/pypi/v/python-dsv-sdk)
![License](https://img.shields.io/github/license/thycotic/python-dsv-sdk)
![Python Versions](https://img.shields.io/pypi/pyversions/python-dsv-sdk)

The [Thycotic](https://thycotic.com/)
[DevOps Secrets Vault](https://thycotic.com/products/devops-secrets-vault-password-management/)
(DSV) Python SDK contains classes that interact with the DSV REST API.

## Install

```shell
python -m pip install python-dsv-sdk
```

## Usage

There are two ways in which you can authorize the `SecretsVault` class to fetch secrets.

- Password Authorization (with `PasswordGrantAuthorizer`)
- Access Token Authorization (with `AccessTokenAuthorizer`)

### Authorizers

#### Password Authorization

If using a traditional `client_id` and a `client_secret` to authenticate in to your DevOps Secrets Vault, you can pass the `PasswordGrantAuthorizer` into the `SecretsVault` class at instantiation. The `PasswordGrantAuthorizer` requires a `base_url`, `username`, and `password`. It _optionally_ takes a `token_path_uri`, but defaults to `/v1/token`.

```python
from thycotic.secrets.vault import PasswordGrantAuthorizer

authorizer = PasswordGrantAuthorizer("https://mytenant.secretsvaultcloud.com/", "my_client_id", "my_client_secret")
```

#### AWS Authorization

If the prequisite AWS authentication provider is configured in DevOps Secrets Vault and  you are running in an AWS Compute environment, you can pass the `AWSGrantAuthorizer` into the `SecretsVault` class at instantiation. The `AWSGrantAuthorizer` requires a `base_url`. It _optionally_ takes a `token_path_uri`, but defaults to `/v1/token`.

The `AWSGrantAuthorizer` optionally takes `access_key`, `secret_key`, `session_token` and `region` parameters. If not specified it uses the default credential chain to get environment variables or the instance profile metadata.

```python
from thycotic.secrets.vault import PasswordGrantAuthorizer

authorizer = AWSGrantAuthorizer("https://mytenant.secretsvaultcloud.com/", "my_access_key", "my_secret_key", "my_session_token", "my_region")
```

#### Access Token Authorization

If you already have a valid `access_token`, you can pass directly via the `AccessTokenAuthorizer`.

```python
from thycotic.secrets.vault import AccessTokenAuthorizer

authorizer = AccessTokenAuthorizer("YgJ1slfZs8ng9bKsRsB-tic0Kh8I...")
```

### Secrets Vault

Instantiate `SecretsVault` by passing your `base_url` and `Authorizer` as arguments:

```python
from thycotic.secrets.vault import SecretsVault

vault = SecretsVault("https://mytenant.secretsvaultcloud.com/", authorizer)
```

Secrets can be fetched using the `get_secret` method, which takes the `secret_path` of the secret and returns a `json` object. Alternatively, you can use pass the json to `VaultSecret` which returns a `dataclass` object representation of the secret:

```python
from thycotic.secrets.vault import VaultSecret

secret = VaultSecret(**vault.get_secret("/test/secret"))

print(f"username: {secret.data['username']}\npassword: {secret.data['password']}")
```

## Using Self-Signed Certificates

When using a self-signed certificate for SSL, the `REQUESTS_CA_BUNDLE` environment variable should be set to the path of the certificate (in `.pem` format). This will negate the need to ignore SSL certificate verification, which makes your application vunerable. Please reference the [`requests` documentation](https://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification) for further details on the `REQUESTS_CA_BUNDLE` environment variable, should you require it.

## Create a Build Environment (optional)

The SDK requires [Python 3.6](https://www.python.org/downloads/) or higher.

First, ensure Python 3.6 is in `$PATH` then run:

```shell
# Clone the repo
git clone https://github.com/thycotic/python-dsv-sdk
cd python-dsv-sdk

# Create a virtual environment
python -m venv venv
. venv/bin/activate

# Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

```

Valid credentials are required to run the unit tests. The credentials should be stored in environment variables or in a `.env` file:

```shell
export DSV_CLIENT_ID="e7f6be68-0acb-4020-9c55-c7b161620199"
export DSV_CLIENT_SECRET="0lYBbBbaXtkMd3WYydhfhuy0rHNFet_jq7QA4ZfEjxU"
export DSV_BASE_URL="https://my.secretsvaultcloud.com/"
export AWS_ACCESS_KEY_ID="ABCD...WXYZ"
export AWS_SECRET_ACCESS_KEY="AbCDEfGHHI...j99KllMmnop90"
export AWS_SESSION_TOKEN="EaCXVzLWVh/////////.../MSJG=="
export AWS_DEFAULT_REGION="us-east-1"
```

The AWS environment variables can be omitted if running in an AWS compute environment and want to use the instance profile.

The tests assume that the client associated with the specified `CLIENT_ID` can read the secret with the path `/test/sdk/simple`.

> Note: The secret path can be changed manually in `test_server.py` to a secret path that the client can access.

To run the tests with `tox`:

```shell
tox
```

To build the package, use [Flit](https://flit.readthedocs.io/en/latest/):

```shell
flit build
```
