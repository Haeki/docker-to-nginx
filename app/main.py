import json
import argparse
import logging
import time
import sys
from logging.handlers import RotatingFileHandler

import docker
from docker.errors import NullResource
from docker.models.containers import Container
from nginx_proxy_manager import ApiHandler


logger = logging.getLogger(f"app.main")

def load_config(config_path: str) -> dict:
    """
    Load a config file from the given path
    """
    _defaults = {
        "letsencrypt": None,
        "nginx_proxy_manager_url": "http://localhost:81/api",
        "nginx_proxy_manager_user": None,
        "nginx_proxy_manager_password": None,
        "attach_network": True,
        "proxy_network": "bridge",
        "verify_ssl": True,
        "proxy_host_defaults": None,
    }
    with open(config_path, "r") as f:
        loaded = json.load(f)
    _defaults.update(loaded)
    _defaults["nginx_proxy_manager_url"] = _defaults["nginx_proxy_manager_url"].rstrip(
        "/"
    )
    return _defaults


def get_env_vars(container: Container):
    """
    Get the environment variables of a container as a dict
    """
    attrs = container.attrs
    return dict(x.split("=", 1) for x in attrs["Config"]["Env"])


def get_matching_hosts(server_names: list[str], domains: dict[str, dict]):
    """
    Check if a host with the given server names is already found in the domains dict
    If multiple servernames match to different hosts, return None
    """
    res: dict = None
    for server_name in server_names:
        if server_name in domains:
            if res and res != domains[server_name]:
                print(f"Server {server_name} is already registered with {res['id']}")
                return None
            res = domains[server_name]
    return res


def attach_to_network(container: Container, network_names: list[str]) -> str | None:
    """
    Attach a container to a network
    """
    networks = {n.name: n for n in container.client.networks.list()}
    for net_name in network_names:
        net = networks.get(net_name, None)
        if net:
            net.connect(container)
            return net_name
    return None


def find_proxy_host(container: Container, proxy_network: list[str]):
    container_networks: dict[str, dict] = container.attrs["NetworkSettings"]["Networks"]
    for pn in proxy_network:
        if network := container_networks.get(pn, None):
            if network["DNSNames"] and container.name in network["DNSNames"]:
                return container.name
            return network["IPAddress"]
    return None


def check_for_changes(
    nginx_proxy_manager: ApiHandler,
    docker_client: docker.DockerClient,
    letsencrypt_config: dict,
    proxy_network,
    attach_network=True,
    proxy_host_defaults=None,
):
    proxy_host_defaults = proxy_host_defaults or {}
    if isinstance(proxy_network, str):
        proxy_network = [proxy_network]
    logger.debug("Looking for changes in container")
    domains = {}
    for host in nginx_proxy_manager.get_proxy_hosts():
        logger.debug("Found host %s", host)
        for domain in host["domain_names"]:
            domains[domain.lower()] = host
    def check_container(container: Container, domains: dict[str, dict]):
        cont_name = container.name
        env_vars = get_env_vars(container)
        if "VIRTUAL_HOST" not in env_vars:
            return
        forward_port = int(env_vars.get("VIRTUAL_PORT", 80))
        server_names = [s.strip() for s in env_vars["VIRTUAL_HOST"].split(",")]
        matching_host = get_matching_hosts(server_names, domains)
        proxy_host = find_proxy_host(container, proxy_network)
        if not proxy_host:
            if attach_network:
                if attached_net := attach_to_network(container, proxy_network):
                    logger.info(f"Attached {cont_name} to network {attached_net}")
                    container.reload()
                    proxy_host = find_proxy_host(container, proxy_network)
                    if not proxy_host:
                        raise NullResource(
                            f"Failed to attach {cont_name} to network {proxy_network}"
                        )
                else:
                    raise NullResource(
                        f"Failed to attach {cont_name} to any network in {proxy_network}"
                    )
            else:
                raise NullResource(
                    f"Container {cont_name} is not attached to any network in {proxy_network}"
                )
        if matching_host:
            logger.debug(f"Found matching host for {server_names}")
            nginx_proxy_manager.update_proxy_host(
                host_data=matching_host,
                domain_names=server_names,
                forward_host=proxy_host,
                forward_port=forward_port,
                letsencrypt_config=letsencrypt_config,
                **proxy_host_defaults
            )
        else:
            logger.info(f"Creating new host for {server_names}")
            nginx_proxy_manager.create_proxy_host(
                domain_names=server_names,
                forward_host=proxy_host,
                forward_port=forward_port,
                letsencrypt_config=letsencrypt_config,
                **proxy_host_defaults
            )
    for container in docker_client.containers.list():
        try:
            check_container(container, domains)
        except Exception:
            logger.exception("Error while checking container %s", container.name)

def setup_logger(log_path: str, verbose: bool):
    app_logger = logging.getLogger("app")
    app_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s - [%(levelname)s]: %(message)s")
    file_handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

def main():
    """
    Main entrypoint for the application
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "--config", "-c", default="config.json", help="Path to the config file"
    )
    argparser.add_argument(
        "--dry-run", "-d", action="store_true", help="Do not make any changes"
    )
    argparser.add_argument(
        "--verbose", "-v", action="store_true", help="Print more information"
    )
    argparser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=60,
        help="Interval in seconds to check for changes",
    )
    argparser.add_argument(
        "--log-path",
        "-l",
        default="logs/docker-to-nginx.log",
        help="Path to the log file",
    )
    args = argparser.parse_args()
    config = load_config(args.config)
    log_path = args.log_path if args.log_path not in ["", "-"] else None
    setup_logger(log_path, args.verbose)

    nginx_proxy_manager = ApiHandler(
        api_url=config["nginx_proxy_manager_url"],
        user=config["nginx_proxy_manager_user"],
        password=config["nginx_proxy_manager_password"],
        verify_ssl=config["verify_ssl"],
    )
    docker_client = docker.from_env()

    if args.dry_run:
        logger.info("Running in dry-run mode")
    while True:
        check_for_changes(
            nginx_proxy_manager=nginx_proxy_manager,
            docker_client=docker_client,
            proxy_network=config["proxy_network"],
            attach_network=config["attach_network"],
            letsencrypt_config=config["letsencrypt"],
            proxy_host_defaults=config["proxy_host_defaults"],
        )
        if args.interval <= 0:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
