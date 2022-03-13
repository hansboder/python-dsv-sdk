""" The Thycotic DevOps Secrets Vault (DSV) SDK API facilitates access to DSV
using bearer token authentication.

Example::
    authorizer = PasswordGrantAuthorizer("https://mytenant.secretsvaultcloud.com/", "my_client_id", "my_client_secret")
    vault = SecretsVault("https://mytenant.secretsvaultcloud.com/", authorizer)
    # to get the secret as a ``dict``
    secret = vault.get_secret("/path/to/secret")
    # or, to use the dataclass
    secret = VaultSecret(**vault.get_secret("/path/to/secret"))"""

from abc import ABC, abstractmethod
import json
import re
import requests
import hashlib
import base64
import hmac
import boto3

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class VaultSecret:
    id: str
    path: str
    attributes: str
    description: str
    data: dict
    created: datetime
    last_modified: datetime
    created_by: str
    last_modified_by: str
    version: float

    DATETIME_FORMAT_PARAMETER = "datetime_format"
    DEFAULT_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # Based on https://gist.github.com/jaytaylor/3660565
    @staticmethod
    def snake_case(camel_cased):
        """Transform to snake case

        Transforms the keys of the given map from camelCase to snake_case.
        """
        return [
            (
                re.compile("([a-z0-9])([A-Z])")
                .sub(r"\1_\2", re.compile(r"(.)([A-Z][a-z]+)").sub(r"\1_\2", k))
                .lower(),
                v,
            )
            for (k, v) in camel_cased.items()
        ]

    def __init__(self, **kwargs):
        # The REST API returns attributes with camelCase names which we replace
        # with snake_case per Python conventions
        datetime_format = self.DEFAULT_DATETIME_FORMAT
        if self.DATETIME_FORMAT_PARAMETER in kwargs:
            datetime_format = kwargs[self.DATETIME_FORMAT_PARAMETER]
        for k, v in self.snake_case(kwargs):
            # @dataclass does not marshal timestamps into datetimes automatically
            if k in ["created", "last_modified"]:
                v = datetime.strptime(v, datetime_format)
            setattr(self, k, v)


class SecretsVaultError(Exception):
    """An Exception that embeds the server response"""

    response: None

    def __init__(self, message, response=None, *args, **kwargs):
        self.message = message
        self.response = response
        super().__init__(*args, **kwargs)


class SecretsVaultAccessError(SecretsVaultError):
    """An Exception that represents a 403"""


class Authorizer(ABC):
    """Main abstract base class for all Authorizer access methods."""

    @staticmethod
    def add_bearer_token_authorization_header(bearer_token, existing_headers={}):
        """Adds an HTTP `Authorization` header containing the `Bearer` token
        :param existing_headers: a ``dict`` containing the existing headers
        :return: a ``dict`` containing the `existing_headers` and the
                `Authorization` header
        :rtype: ``dict``
        """

        return {
            "Authorization": "Bearer " + bearer_token,
            **existing_headers,
        }

    @abstractmethod
    def get_access_token(self):
        """Returns the access_token from a Grant Request"""

    def headers(self, existing_headers={}):
        """Returns a dictionary containing headers for REST API calls"""
        return self.add_bearer_token_authorization_header(
            self.get_access_token(), existing_headers
        )


class AccessTokenAuthorizer(Authorizer):
    """Allows the use of a pre-existing access token to authorize REST API
    calls.
    """

    def get_access_token(self):
        return self.access_token

    def __init__(self, access_token):
        self.access_token = access_token


class PasswordGrantAuthorizer(Authorizer):
    """Allows the use of a username and password to be used to authorize REST
    API calls.
    """

    @staticmethod
    def _get_access_grant(token_url, client_id, client_secret):
        """Gets an Access Grant by calling the DSV REST API ``token`` endpoint

        :raise :class:`SecretsVaultError` when the server returns anything other
               than a valid Access Grant"""

        response = requests.post(
            token_url,
            json={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
        )

        try:
            return json.loads(SecretsVault.process(response).content)
        except json.JSONDecodeError:
            raise SecretsVaultError(response)

    def _refresh_access_grant(self, seconds_of_drift=300):
        """Refreshes the Access Grant if it has expired or will in the next
        `seconds_of_drift` seconds.

        :raise :class:`SecretsVaultError` when the server returns anything other
               than a valid Access Grant"""

        if (
            hasattr(self, "access_grant")
            and self.access_grant_refreshed
            + timedelta(seconds=self.access_grant["expiresIn"] + seconds_of_drift)
            > datetime.now()
        ):
            return
        else:
            self.access_grant = self._get_access_grant(
                self.token_url, self.client_id, self.client_secret
            )
            self.access_grant_refreshed = datetime.now()

    def __init__(self, base_url, client_id, client_secret, token_path_uri="/v1/token"):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = base_url.rstrip(
            "/") + "/" + token_path_uri.lstrip("/")
        self.grant_request = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

    def get_access_token(self):
        self._refresh_access_grant()
        return self.access_grant["accessToken"]


class AWSGrantAuthorizer(Authorizer):
    """Allows the use of an AWS profile to authorize REST API calls.
    """

    @staticmethod
    def _get_access_grant(token_url, access_key, secret_key, session_token, region):
        """Gets an Access Grant by calling the DSV REST API ``token`` endpoint 
        using AWS credentials.
        See https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

        :raise :class:`SecretsVaultError` when the server returns anything other
               than a valid Access Grant"""

        region = "us-east-1" if region is None else region
        endpoint = 'sts.amazonaws.com'

        if region != "us-east-1":
            endpoint = f"sts.{region}.amazonaws.com"

        datetime_now = datetime.utcnow()
        amz_date = datetime_now.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = datetime_now.strftime('%Y%m%d')

        pre_request = requests.Request(
            method='POST',
            url=f"https://{endpoint}",
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                     "Host": endpoint, "X-Amz-Date": amz_date},
            data='Action=GetCallerIdentity&Version=2011-06-15',
        )

        if session_token:
            pre_request.headers["X-Amz-Security-Token"] = session_token

        request = pre_request.prepare()

        # create canonical request
        canonical_uri = "/"
        canonical_querystring = ""
        canonical_headers = "".join(
            f"{h.lower()}:{request.headers[h]}\n" for h in sorted(request.headers))
        payload_hash = hashlib.sha256(request.body.encode('utf-8')).hexdigest()
        signed_headers = ';'.join(h.lower() for h in sorted(request.headers))
        canonical_request = f"{request.method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        # create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{region}/sts/aws4_request"
        request_hash = hashlib.sha256(
            canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{request_hash}"

        # calculate signature
        key = f"AWS4{secret_key}".encode('utf-8')
        for message in [date_stamp, region, "sts", "aws4_request"]:
            key = hmac.new(key, message.encode(
                'utf-8'), hashlib.sha256).digest()

        signature = hmac.new(key, string_to_sign.encode(
            'utf-8'), hashlib.sha256).hexdigest()

        # create sts authorization header and normalize
        authorization_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        request.headers['Authorization'] = authorization_header
        headers = json.dumps({h: [request.headers[h]]
                             for h in request.headers})

        response = requests.post(
            token_url,
            json={
                "aws_headers": base64.b64encode(headers.encode('utf-8')).decode('utf-8'),
                "aws_body":  base64.b64encode(request.body.encode('utf-8')).decode('utf-8'),
                "grant_type": "aws_iam",
            },
        )

        try:
            return json.loads(SecretsVault.process(response).content)
        except json.JSONDecodeError:
            raise SecretsVaultError(response)

    def _refresh_access_grant(self, seconds_of_drift=300):
        """Refreshes the Access Grant if it has expired or will in the next
        `seconds_of_drift` seconds.

        Use boto3 session credential provider to get refreshed AWS credentials
        if no explicit access key and secret key are set as the instance credentials
        will have changed since the previous authentication attempt

        :raise :class:`SecretsVaultError` when the server returns anything other
               than a valid Access Grant"""

        if (
            hasattr(self, "access_grant")
            and self.access_grant_refreshed
            + timedelta(seconds=self.access_grant["expiresIn"] + seconds_of_drift)
            > datetime.now()
        ):
            return
        else:
            access_key = self.access_key
            secret_key = self.secret_key
            session_token = self.session_token
            region = self.region

            if (self.access_key is None and self.secret_key is None):
                session = boto3.Session()
                credentials = session.get_credentials().get_frozen_credentials()
                access_key = credentials.access_key
                secret_key = credentials.secret_key
                session_token = credentials.token
                region = session.region_name

            self.access_grant = self._get_access_grant(
                self.token_url, access_key, secret_key, session_token, region
            )
            self.access_grant_refreshed = datetime.now()

    def __init__(self, base_url, access_key=None, secret_key=None, session_token=None, region="us-east-1", token_path_uri="/v1/token"):
        self.base_url = base_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.region = region
        self.token_url = base_url.rstrip(
            "/") + "/" + token_path_uri.lstrip("/")

    def get_access_token(self):
        self._refresh_access_grant()
        return self.access_grant["accessToken"]


class SecretsVault:
    """A class that uses bearer token authentication to access the DSV API.

    It Uses :attr:`base_url`, :attr:`authorizer` to make calls to the DSV REST 
    API
    """

    SECRET_PATH_URI = "secrets"

    @staticmethod
    def process(response):
        """Process the response raising an error if the call was unsuccessful

        :param response: the response from the server
        :type response: :class:`~requests.Response`
        :return: the response if the call was successful
        :rtype: :class:`~requests.Response`
        :raises: :class:`SecretsVaultAccessError` when the caller does not have
                access to the secret
        :raises: :class:`SecretsAccessError` when the server responses with any
                other error"""

        if response.status_code >= 200 and response.status_code < 300:
            return response
        if response.status_code >= 400 and response.status_code < 500:
            raise SecretsVaultAccessError(
                json.loads(response.content)["message"], response
            )
        raise SecretsVaultError(response)

    def __init__(
        self,
        base_url,
        authorizer: Authorizer,
        api_path_uri="/v1",
    ):
        """
        :param base_url: The DSV URL i.e. mytenant.secretsvaultcloud.com
        :type base_url: str
        :param authorizer: The Authorizer class used to authenticate to the DSV
            REST API
        :type authorizer: Authorizer class
        """

        self.base_url = base_url.rstrip("/")
        self.authorizer = authorizer
        self.api_url = base_url.rstrip("/") + "/" + api_path_uri.strip("/")

    def headers(self):
        """Returns a dictionary containing HTTP headers."""
        return self.authorizer.headers()

    def get_secret_json(self, secret_path):
        """Gets a secret from DSV

        :param secret_path: the path to the secret
        :type secret_path: str
        :return: a JSON formatted string representation of the secret
        :rtype: ``str``
        :raise: :class:`SecretsVaultAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretsVaultError` when the REST API call fails for
                any other reason"""

        return self.process(
            requests.get(
                f"{self.api_url}/{self.SECRET_PATH_URI}/{secret_path.lstrip('/')}",
                headers=self.headers(),
            )
        ).text

    def get_secret(self, secret_path):
        """Gets a secret

        :param secret_path: the path to the secret
        :type secret_path: str
        :return: a ``dict`` representation of the secret
        :rtype: ``dict``
        :raise: :class:`SecretsVaultAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretsVaultError` when the REST API call fails for
                any other reason"""
        response = self.get_secret_json(secret_path)

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            raise SecretsVaultError(response)
