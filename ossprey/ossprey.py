from __future__ import annotations
import json
import logging
import os
import requests
import time

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from typing import Tuple, Final

logger = logging.getLogger(__name__)

# Global Cognito Constants
USER_POOL_DOMAIN = os.environ.get("USER_POOL_DOMAIN", "ossprey-auth")
CLIENT_ID = os.environ.get("CLIENT_ID", "77o2e7rf9ulhbpo78h6rdirqin")
REGION = os.environ.get("REGION", "eu-west-1")
TOKEN_ENDPOINT = f"https://{USER_POOL_DOMAIN}.auth.{REGION}.amazoncognito.com/oauth2/token"


class Ossprey:

    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key

        if not self.api_key:
            raise Exception("API Key is null or empty")
        
        self.auth()
        self.session = self.create_session()

    def auth(self) -> None:
        """Authenticate with API Refresh Key and retrieve a temporary access token

        Raises:
            Exception: Failed to retrieve access token
            Exception: Failed to authenticate with API Key
        """
        logger.debug("Authenticating with API Key")
        data = {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": self.api_key
        }

        response = requests.post(TOKEN_ENDPOINT, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if response.status_code != 200:
            logger.error("Failed to retrieve access token")
            logger.debug(f"Status code: {response.status_code}")
            logger.debug(f"Response: {response.text}")
            raise Exception(f"Authentication failed: {response.text}")

        access_token = response.json().get("access_token")
        if not access_token:
            logger.error("Access token is null or empty")
            raise Exception("Authentication failed: Access token is null or empty")

        self.access_token = access_token

        logger.debug("Authentication succeeded")

    # This takes a python dictionary and submits it to the API
    def validate(self, minibom: dict) -> dict | None:

        response = self.submit(minibom)

        match response.status_code:
            case 200:
                return response.json()
            case 202:
                json = response.json()
                sbom_id = json['sbom_id']
                scan_id = json['scan_id']
                return self.wait_for_completion(sbom_id, scan_id)
            case 429:
                logger.error("Rate limit exceeded")
                return None
            case _:
                logger.error("Failed to submit request")
                logger.debug(f"Status code: {response.status_code}")
                logger.debug(f"Response: {response.text}")

                data = response.json()
                if "message" in data:
                    logger.error(data["message"])
                return None

    def submit(self, json_bom: dict) -> requests.Response:

        # Get the url
        url = self.api_url + '/submit'

        logger.debug(f"JSON Submission: {json.dumps(json_bom)}")

        # Submit bom to API
        json_data = {"sbom": json_bom}
        headers = {'Content-Type': 'application/json', 'Authorization': f"Bearer {self.access_token}"}
        response = self.session.post(url, headers=headers, json=json_data)

        return response
        
    def wait_for_completion(self, sbom_id: str, scan_id: str) -> dict:
        url = self.api_url + '/status'

        params = {"sbom_id": sbom_id, "scan_id": scan_id}

        headers = {'Content-Type': 'application/json', 'Authorization': f"Bearer {self.access_token}"}
        for i in range(1, 20):
            time.sleep(i * i)

            response = self.session.get(url, headers=headers, params=params)
            if response.status_code not in [200, 202]:
                logger.error("Error returned when retrieving the results")
                logger.debug(f"Status code: {response.status_code}")
                logger.debug(f"Response: {response.text}")
                raise Exception("Error returned when retrieving the results")

            ret = response.json()
            if ret['status'] == 'SUCCEEDED':
                if 'output' in ret:
                    return ret['output']
                else:
                    raise Exception("Error no SBOM returned")

        logger.error("Scan took too long to complete")
        raise Exception("Scan took too long to complete")

    @staticmethod
    def create_session() -> requests.Session:
        """Return a Session that transparently retries on 503."""
        
        _RETRIES: Final = 5
        _BACKOFF: Final = 1.0  # seconds
        _STATUS_FORCELIST = (503,)
        _ALLOWED_METHODS: Final[Tuple[str, ...]] = (
            "GET",
            "POST",
        )

        retry = Retry(
            total=_RETRIES,
            backoff_factor=_BACKOFF,
            status_forcelist=_STATUS_FORCELIST,
            allowed_methods=_ALLOWED_METHODS,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        sess = requests.Session()
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess
