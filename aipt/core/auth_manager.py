import asyncio
import json
import time
from typing import Dict, Optional, Any
from urllib.parse import urljoin
import logging

from .config import AuthConfig
from .async_engine import AsyncHTTPClient


class AuthManager:
    def __init__(self, config: AuthConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client
        self.authenticated = False
        self.auth_headers: Dict[str, str] = {}
        self.auth_cookies: Dict[str, str] = {}
        self.token_expiry: float = 0
        self.logger = logging.getLogger(__name__)

    async def authenticate(self) -> bool:
        if not self.config.enabled:
            return True

        try:
            if self.config.type == "token":
                return await self._token_auth()
            elif self.config.type == "basic":
                return await self._basic_auth()
            elif self.config.type == "oauth":
                return await self._oauth_auth()
            elif self.config.type == "form":
                return await self._form_auth()
            elif self.config.type == "cookie":
                return await self._cookie_auth()
            else:
                self.logger.warning(f"Unknown auth type: {self.config.type}")
                return False
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            return False

    async def _token_auth(self) -> bool:
        prefix = self.config.token_prefix
        token = self.config.token
        header_name = self.config.token_header

        self.auth_headers[header_name] = f"{prefix} {token}" if prefix else token
        self.authenticated = True
        self.logger.info("Token authentication configured")
        return True

    async def _basic_auth(self) -> bool:
        import base64
        credentials = base64.b64encode(
            f"{self.config.username}:{self.config.password}".encode()
        ).decode()
        self.auth_headers["Authorization"] = f"Basic {credentials}"
        self.authenticated = True
        self.logger.info("Basic authentication configured")
        return True

    async def _oauth_auth(self) -> bool:
        if not self.config.oauth_token_url:
            self.logger.error("OAuth token URL not configured")
            return False

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.oauth_client_id,
            "client_secret": self.config.oauth_client_secret,
        }

        if self.config.oauth_scope:
            data["scope"] = self.config.oauth_scope

        response = await self.client.post(
            self.config.oauth_token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.is_error:
            self.logger.error(f"OAuth token request failed: {response.status}")
            return False

        try:
            token_data = json.loads(response.text)
            access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in", 3600)

            if access_token:
                self.auth_headers["Authorization"] = f"Bearer {access_token}"
                self.token_expiry = time.time() + expires_in
                self.authenticated = True
                self.logger.info("OAuth authentication successful")
                return True
        except json.JSONDecodeError:
            self.logger.error("Invalid OAuth response")

        return False

    async def _form_auth(self) -> bool:
        if not self.config.login_url:
            self.logger.error("Login URL not configured")
            return False

        response = await self.client.post(
            self.config.login_url,
            data=self.config.login_form_data
        )

        if response.is_error:
            self.logger.error(f"Form login failed: {response.status}")
            return False

        if self.config.login_success_indicator:
            if self.config.login_success_indicator in response.text:
                self.authenticated = True
                self.auth_cookies = response.cookies
                self.logger.info("Form authentication successful")
                return True
            else:
                self.logger.warning("Login success indicator not found")
                return False

        if response.status == 200 or response.status == 302:
            self.authenticated = True
            self.auth_cookies = response.cookies
            self.logger.info("Form authentication successful (status-based)")
            return True

        return False

    async def _cookie_auth(self) -> bool:
        self.auth_cookies = self.config.cookie_auth
        self.authenticated = True
        self.logger.info("Cookie authentication configured")
        return True

    async def refresh_auth(self) -> bool:
        if not self.config.enabled:
            return True

        if time.time() > self.token_expiry - 300:
            self.logger.info("Refreshing authentication")
            return await self.authenticate()

        return True

    def get_auth_headers(self) -> Dict[str, str]:
        return self.auth_headers.copy()

    def get_auth_cookies(self) -> Dict[str, str]:
        return self.auth_cookies.copy()

    async def apply_auth(self, request_headers: Dict[str, str]) -> Dict[str, str]:
        headers = request_headers.copy()
        headers.update(self.auth_headers)
        return headers
