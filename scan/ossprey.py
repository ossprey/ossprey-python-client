import json
import logging
import requests

logger = logging.getLogger(__name__)

# Global Cognito Constants
USER_POOL_DOMAIN = "ossprey-auth"
CLIENT_ID = "77o2e7rf9ulhbpo78h6rdirqin"
REGION = "eu-west-1"
TOKEN_ENDPOINT = f"https://{USER_POOL_DOMAIN}.auth.{REGION}.amazoncognito.com/oauth2/token"


class Ossprey:

    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key

        if not self.api_key:
            raise Exception("API Key is null or empty")
        
        self.auth()

    def auth(self):
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

    def validate(self, json_bom):

        # Get the url
        url = self.api_url + '/ossprey'

        logger.debug(f"JSON Submission: {json.dumps(json_bom)}")

        # Submit bom to API
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f"Bearer {self.access_token}"
        response = requests.post(url, headers=headers, json=json_bom)
        if response.status_code != 200:
            logger.error("Failed to validate the BOM")
            logger.debug(f"Status code: {response.status_code}")
            logger.debug(f"Response: {response.text}")

            data = response.json()
            if "message" in data:
                logger.error(data["message"])
            return None

        ret = response.json()
        return ret
