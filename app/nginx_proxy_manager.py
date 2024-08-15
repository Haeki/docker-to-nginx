import logging
from typing import Iterable, Mapping
from datetime import datetime, timedelta

import requests

logger = logging.getLogger(f"app.{__name__}")


def parse_datetime(date_str: str) -> datetime:
    """
    Parse a date string into a datetime object
    Tries to parse the date string as a timestamp first, then as an iso formatted string

    Args:
        date_str (str): the date string to parse

    Returns:
        datetime: the parsed datetime object

    Raises:
        ValueError: if the date string cannot be parsed
    """
    try:
        return datetime.fromtimestamp(float(date_str))
    except ValueError:
        return datetime.fromisoformat(date_str)


def time_until(date: datetime) -> timedelta:
    """
    Calculate the time until a given date.
    Works with timezone aware dates and naive dates.
    If the date is in the past, the timedelta will be negative

    Args:
        date (datetime): the date to calculate the time until

    Returns:
        timedelta: the time delta from now until the given date.
    """
    if date.tzinfo is None:
        return date - datetime.now()
    return date - datetime.now(date.tzinfo)


def compare_data(data1, data2) -> None:
    """
    Compare two dictionaries and return True if they are equal

    Args:
        data1 (dict): the first dictionary
        data2 (dict): the second dictionary

    Returns:
        bool: True if the dictionaries are equal, False otherwise
    """
    if isinstance(data1, (float, int)) and isinstance(data2, (float, int)):
        return data1 == data2
    if isinstance(data1, str) and isinstance(data2, str):
        return data1 == data2
    if isinstance(data1, Mapping) and isinstance(data2, Mapping):
        for key in data1:
            if key not in data2:
                return False
            if not compare_data(data1[key], data2[key]):
                return False
        return True
    if isinstance(data1, Iterable) and isinstance(data2, Iterable):
        if len(data1) != len(data2):
            return False
        for i in range(len(data1)):
            if not compare_data(data1[i], data2[i]):
                return False
        return True
    if type(data1) != type(data2):
        return False
    return data1 == data2


def get_token(api_url: str, user: str, password: str, verify_ssl: bool = True) -> dict:
    """_summary_

    Args:
        api_url (str): the url of the nginx proxy manager api
        user (str): the user to authenticate with
        password (str): the password to authenticate with
        verify_ssl (bool, optional): If the api url is https should the certificate be validated. Defaults to True.

    Returns:
        dict: the token and expiration date
    """
    logger.debug("Requesting new token from nginx proxy manager for user %s", user)
    resp = requests.post(
        f"{api_url}/tokens",
        verify=verify_ssl,
        timeout=60,
        json={"identity": user, "secret": password},
    )
    resp.raise_for_status()
    res = resp.json()
    expire_date = parse_datetime(res["expires"])
    res["expires"] = expire_date
    logger.debug(
        "Received new token for user %s, expires at %s",
        user,
        expire_date.isoformat(timespec="minutes"),
    )
    return res


def get_proxy_hosts(api_url: str, token: str, verify_ssl: bool = True) -> list[dict]:
    """
    Get all proxy hosts visible to the user from the nginx proxy manager

    Args:
        api_url (str): the url of the nginx proxy manager api
        token (str): the token to authenticate with
        verify_ssl (bool, optional): If the api url is https should the certificate be validated. Defaults to True.

    Returns:
        list[dict]: the proxy host returned by the api
    """
    logger.debug("Requesting proxy hosts from nginx proxy manager")
    resp = requests.get(
        f"{api_url}/nginx/proxy-hosts",
        verify=verify_ssl,
        timeout=60,
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    res = resp.json()
    logger.debug("Received %d proxy hosts from nginx proxy manager", len(res))
    return res


def update_proxy_host(
    api_url: str,
    token: str,
    host_data: dict,
    domain_names: list[str],
    forward_port: int,
    forward_host: str,
    letsencrypt_config: dict,
    verify_ssl: bool = True,
    **kwargs,
) -> dict:
    """
    Update an existing proxy host in nginx proxy manager

    Args:
        api_url (str): the url of the nginx proxy manager api
        token (str): the token to authenticate with
        host_data (dict): the data of the existing host
        domain_names (list[str]): the domain names that should be proxied
        forward_port (int): the port the traffic should be forwarded to
        forward_host (str): the host the traffic should be forwarded to
        letsencrypt_config (dict): the configuration for letsencrypt
        verify_ssl (bool, optional): If the api url is https should the certificate be validated. Defaults to True.

    Returns:
        dict: either the response from the api (usually the created proxy host) or the host_data if no changes were detected
    """
    data = {
        "domain_names": domain_names,
        "forward_host": forward_host,
        "forward_port": forward_port,
    }
    if letsencrypt_config:
        data["meta"] = _create_letsencrypt_config(letsencrypt_config)
    data.update(kwargs)
    if compare_data(data, host_data):
        logger.debug("No changes detected for host %s", host_data["id"])
        return host_data
    logger.info("Updating proxy host %s", host_data["id"])
    logger.debug("Data: %s", data)
    resp = requests.put(
        f"{api_url}/nginx/proxy-hosts/{host_data['id']}",
        verify=verify_ssl,
        timeout=60,
        json=data,
        headers={"Authorization": f"Bearer {token}"},
    )
    logger.debug("Response: %s", resp.text)
    resp.raise_for_status()
    res = resp.json()
    logger.debug("Updated proxy host %s", res)
    return res


def _create_letsencrypt_config(letsencrypt_config: dict) -> dict:
    """
    Args:
        letsencrypt_config (dict): make sure the letsencrypt config is valid

    Returns:
        dict: A letsencrypt config that can be used for the meta field in the proxy host payload
    """
    if letsencrypt_config:
        if "letsencrypt_agree" not in letsencrypt_config:
            letsencrypt_config["letsencrypt_agree"] = True
        if "dns_provider" in letsencrypt_config:
            letsencrypt_config["dns_challenge"] = True
        if dns_cloudflare_api_token := letsencrypt_config.pop(
            "dns_cloudflare_api_token", None
        ):
            letsencrypt_config["dns_provider_credentials"] = (
                f"# Cloudflare API token\r\ndns_cloudflare_api_token={dns_cloudflare_api_token}"
            )
        return letsencrypt_config
    return {"letsencrypt_agree": False, "dns_challenge": False}


def create_proxy_host(
    api_url: str,
    token: str,
    domain_names: list[str],
    forward_port: int,
    forward_host: str,
    letsencrypt_config: dict,
    verify_ssl: bool = True,
    **kwargs,
) -> dict:
    """
    Create a new proxy host in nginx proxy manager

    Args:
        api_url (str): the url of the nginx proxy manager api
        token (str): the token to authenticate with
        domain_names (list[str]): the domain names that should be proxied
        forward_port (int): the port the traffic should be forwarded to
        forward_host (str): the host the traffic should be forwarded to
        letsencrypt_config (dict): the configuration for letsencrypt
        verify_ssl (bool, optional): If the api url is https should the certificate be validated. Defaults to True.

    Returns:
        dict: the response from the api (usually the created proxy host)
    """
    payload = {
        "domain_names": domain_names,
        "forward_scheme": "http",
        "forward_host": forward_host,
        "forward_port": forward_port,
        "block_exploits": True,
        "access_list_id": "0",
        "certificate_id": "new",
        "ssl_forced": True,
        "meta": _create_letsencrypt_config(letsencrypt_config),
        "advanced_config": "",
        "locations": [],
        "caching_enabled": False,
        "allow_websocket_upgrade": False,
        "http2_support": False,
        "hsts_enabled": False,
        "hsts_subdomains": False,
    }
    payload.update(kwargs)
    logger.debug(
        "Creating new proxy host for domains %s proxied to %s:%s",
        domain_names,
        forward_host,
        forward_port,
    )
    resp = requests.post(
        f"{api_url}/nginx/proxy-hosts",
        verify=verify_ssl,
        timeout=60,
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    resp.raise_for_status()
    res = resp.json()
    logger.debug("Created new proxy host: %s", res)
    return res


class ApiHandler:
    """
    Class to Handle interactions with the nginx proxy manager api
    """

    def __init__(self, api_url, user, password, verify_ssl=True):
        self.api_url = api_url
        self._user = user
        self._password = password
        self._token: dict = None
        self.verify_ssl = verify_ssl

    @property
    def token(self) -> str:
        """
        Get the token for the nginx proxy manager api
        If the token does not exist or is expired, a new one will be requested

        Returns:
            str: the token for the nginx proxy manager api
        """
        if self._token:
            if time_until(self._token["expires"]).total_seconds() > 10:
                return self._token["token"]
        self._token = self.get_token()
        return self._token["token"]

    def get_token(self):
        """
        Get a new token from the nginx proxy manager

        Returns:
            dict: A dictionary containing the token and the expiration date
        """
        return get_token(self.api_url, self._user, self._password, self.verify_ssl)

    def get_proxy_hosts(self):
        """
        Retrieve all proxy hosts from nginx proxy manager

        Returns:
            _type_: list[dict]
        """
        return get_proxy_hosts(self.api_url, self.token, self.verify_ssl)

    def update_proxy_host(
        self,
        host_data: dict,
        domain_names: list[str],
        forward_port: int,
        forward_host: str,
        letsencrypt_config: dict,
        **kwargs,
    ) -> dict:
        """
        Update an existing proxy host in nginx proxy manager

        Args:
            host_data (dict): the data of the existing host
            domain_names (list[str]): the domain names that should be proxied
            forward_port (int): the port the traffic should be forwarded to
            forward_host (str): the host the traffic should be forwarded to
            letsencrypt_config (dict): the configuration for letsencrypt

        Returns:
            dict: either the response from the api (usually the created proxy host) or the host_data if no changes were detected
        """
        return update_proxy_host(
            api_url=self.api_url,
            token=self.token,
            host_data=host_data,
            domain_names=domain_names,
            forward_port=forward_port,
            forward_host=forward_host,
            letsencrypt_config=letsencrypt_config,
            **kwargs,
        )

    def create_proxy_host(
        self,
        domain_names: list[str],
        forward_port: int,
        forward_host: str,
        letsencrypt_config: dict,
        **kwargs,
    ) -> None:
        """
        Create a new proxy host in nginx proxy manager

        Args:
            domain_names (list[str]): list of domain names that should be proxied
            forward_port (int): the port the traffic should be forwarded to
            forward_host (str): the host the traffic should be forwarded to
            letsencrypt_config (dict): configuration for letsencrypt

        Returns:
            None
        """
        return create_proxy_host(
            api_url=self.api_url,
            token=self.token,
            verify_ssl=self.verify_ssl,
            domain_names=domain_names,
            forward_port=forward_port,
            forward_host=forward_host,
            letsencrypt_config=letsencrypt_config,
            **kwargs,
        )
