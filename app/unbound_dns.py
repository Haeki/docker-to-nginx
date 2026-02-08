import requests
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class UnboundDnsHandler:
    def __init__(self, api_url: str, api_key: str, api_secret: str):
        """
        Initialize the Unbound DNS Handler.

        Args:
            api_url: Base URL of the OPNsense firewall (e.g., https://firewall.example.com)
            api_key: API key for authentication
            api_secret: API secret for authentication
        """
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (api_key, api_secret)
        # Disable SSL verification if using self-signed certs (not recommended for production)

    def list_overrides(self, host: str = None) -> dict:
        """List all host overrides."""
        url = f"{self.api_url}/api/unbound/settings/searchHostOverride/"
        response = self.session.get(url, params={"host": host} if host else None)
        response.raise_for_status()
        return response.json()

    def list_aliases(self) -> dict:
        """List all host aliases."""
        url = f"{self.api_url}/api/unbound/settings/searchHostAlias/"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_overrides_by(self, key: str = "server"):
        overrides = self.list_overrides()["rows"]
        res: dict[tuple[str, str], list[dict]] = {}
        for o in overrides:
            if key == "fqdn":
                res.setdefault((o["hostname"], o["domain"]), []).append(o)
                continue
            res.setdefault(o[key], []).append(o)
        return res

    def get_aliases_by(self, key: str = "host"):
        aliases = self.list_aliases()["rows"]
        res: dict[tuple[str, str], list[dict]] = {}
        for a in aliases:
            if key == "fqdn":
                res.setdefault((a["hostname"], a["domain"]), []).append(a)
                continue
            res.setdefault(a[key], []).append(a)
        return res

    def get_fqdns_for_server(self, server: str) -> set[tuple[str, str]]:
        overrides = self.get_overrides_by("server").get(server, [])
        aliases = self.get_aliases_by("host")
        domains = {}
        for o in overrides:
            domains[(o["hostname"], o["domain"])] = o
            for a in aliases.get(o["uuid"], []):
                domains[(a["hostname"], a["domain"])] = a
        return domains

    def find_entries(self, hostname: str, domain: str) -> Optional[dict]:
        """Find a host entry by hostname and domain."""
        res = []
        overrides = self.get_overrides_by("fqdn").get((hostname, domain), [])
        res.extend(overrides)
        aliases = self.get_aliases_by("fqdn").get((hostname, domain), [])
        res.extend(aliases)
        return res if res else None

    def get_override(self, host_uuid: str) -> dict:
        """Get a host override by UUID."""
        url = f"{self.api_url}/api/unbound/settings/get_host_override/{host_uuid}"
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        override = data["host"]
        override["uuid"] = host_uuid
        return override

    def get_alias(self, alias_uuid: str) -> dict:
        """Get a host alias by UUID."""
        url = f"{self.api_url}/api/unbound/settings/get_host_alias/{alias_uuid}"
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        alias = data["alias"]
        alias["uuid"] = alias_uuid
        return alias

    def add_host(
        self,
        hostname: str,
        domain: str,
        server: str,
        enabled: bool = True,
        description: str = "",
        ttl: Optional[int] = None,
        txtdata: str = "",
    ) -> dict:
        """Add a new Host Entry"""
        logger.info("Adding host override for %s: %s.%s", server, hostname, domain)
        url = f"{self.api_url}/api/unbound/settings/add_host_override/"
        payload = {
            "host": {
                "enabled": int(enabled),
                "hostname": hostname,
                "domain": domain,
                "server": server,
                "description": description,
                "ttl": ttl,
                "txtdata": txtdata,
            }
        }
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

    def add_alias(
        self,
        host_uuid: str,
        hostname: str,
        domain: str,
        enabled: bool = True,
        description: str = "",
    ) -> dict:
        """
        Add a new host alias.

        Args:
            host_uuid: UUID of the parent host override
            hostname: The alias hostname
            domain: The domain name
            enabled: Whether the alias is enabled
            description: Optional description
        """
        logger.info("Adding alias for host %s: %s.%s", host_uuid, hostname, domain)
        url = f"{self.api_url}/api/unbound/settings/add_host_alias/"
        payload = {
            "alias": {
                "enabled": int(enabled),
                "host": host_uuid,
                "hostname": hostname,
                "domain": domain,
                "description": description,
            }
        }
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

    def add_entry(
        self,
        hostname: str,
        domain: str,
        server: str,
        check_existing: bool = True,
        host_fqdn: str | tuple[str, str] = None,
        host_uuid: str = None,
        enabled: bool = True,
        description: str = "",
        ttl: Optional[int] = None,
        txtdata: str = "",
    ) -> dict:
        """Add a new entry for a given fqdn"""
        if check_existing and (e := self.find_entries(hostname, domain)):
            logger.info("Entry for %s.%s already exists, skipping creation: %s", hostname, domain, e)
            return e

        if host_uuid:
            res = self.add_alias(
                host_uuid=host_uuid,
                hostname=hostname,
                domain=domain,
                enabled=enabled,
                description=description,
            )
            self.reconfigure()
            return self.get_alias(res["uuid"])

        if host_fqdn:
            if isinstance(host_fqdn, str):
                host_fqdn = tuple(host_fqdn.split(".", 1))
                overrides = self.get_overrides_by("fqdn").get((hostname, domain))
                if not overrides:
                    raise ValueError(f"No host override found for {host_fqdn}")
                override = overrides[0]
                res = self.add_alias(
                    host_uuid=override["uuid"],
                    hostname=hostname,
                    domain=domain,
                    enabled=enabled,
                    description=description,
                )
                self.reconfigure()
                return self.get_alias(res["uuid"])

        if overrides := self.get_overrides_by("server").get(server):
            override = overrides[0]
            res = self.add_alias(
                host_uuid=override["uuid"],
                hostname=hostname,
                domain=domain,
                enabled=enabled,
                description=description,
            )
            self.reconfigure()
            return self.get_alias(res["uuid"])
        res = self.add_host(
            hostname=hostname,
            domain=domain,
            server=server,
            enabled=enabled,
            description=description,
            ttl=ttl,
            txtdata=txtdata,
        )
        self.reconfigure()
        return self.get_override(res["uuid"])

    def delete_host(self, host_uuid: str) -> dict:
        """Delete a host override by UUID."""
        url = f"{self.api_url}/api/unbound/settings/del_host_override/{host_uuid}"
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()

    def delete_alias(self, alias_uuid: str) -> dict:
        """Delete a host alias by UUID."""
        url = f"{self.api_url}/api/unbound/settings/del_host_alias/{alias_uuid}"
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()

    def reconfigure(self) -> dict:
        """Apply configuration changes by reconfiguring the Unbound service."""
        url = f"{self.api_url}/api/unbound/service/reconfigure/"
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()

    def status(self) -> dict:
        """Get the current status of the Unbound service."""
        url = f"{self.api_url}/api/unbound/service/status/"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()


def main():
    # Example usage
    api_url = "https://firewall.haeki.de"
    key="RVTvdVVmvYLmj1CBgZdmGkGJ6mEf/9kAV6csPJjShWLRonONauqwlH88qxwwW9u5PXIa2gEmL39Dk0BS"
    secret="+9cS9BGY+wI/P3FRk4ybzqhz+JgstDznEYGjyxUWuSI0lxtD6SHm7U/DLmiZ6WBZb0PfWA7erwobj7kE"

    handler = UnboundDnsHandler(api_url, key, secret)
    print(handler.list_overrides())

if __name__ == "__main__":    main()