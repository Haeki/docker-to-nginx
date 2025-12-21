import json
import argparse
import logging
import time
import sys
import threading
import signal
from logging.handlers import RotatingFileHandler

import docker
from docker.errors import NullResource, NotFound
from docker.models.containers import Container
from docker.models.networks import Network
from nginx_proxy_manager import ApiHandler


logger = logging.getLogger(f"app.main")


def load_config(config_path: str) -> dict:
    """
    Load a config file from the given path
    """
    _defaults = {
        "letsencrypt": None,
        "nginx_proxy_manager_url": None,
        "nginx_proxy_manager_user": None,
        "nginx_proxy_manager_password": None,
        "attach_network": "container",
        "proxy_network": None,
        "proxy_container": None,
        "proxy_container_label": {"org.label-schema.name": "nginx-proxy-manager"},
        "verify_ssl": True,
        "proxy_host_defaults": None,
        "own_container": None,
        "own_container_label": {"de.haeki.name": "docker-to-nginx"},
        "attach_self": "container",
    }
    with open(config_path, "r") as f:
        loaded = json.load(f)
    _defaults.update(loaded)
    if _defaults["nginx_proxy_manager_url"]:
        _defaults["nginx_proxy_manager_url"] = _defaults[
            "nginx_proxy_manager_url"
        ].rstrip("/")
    return _defaults


def get_env_vars(container: Container) -> dict:
    """
    Get the environment variables of a container as a dict
    """
    attrs = container.attrs
    return dict(x.split("=", 1) for x in attrs["Config"]["Env"])


def get_labels(container: Container) -> dict:
    """
    Get the labels of a container as a dict
    """
    return container.attrs["Config"]["Labels"]


def get_matching_hosts(domain_names: list[str], domains: dict[str, dict]):
    """
    Check if a host with the given server names is already found in the domains dict
    If multiple server names match to different hosts, return None
    """
    res: dict = None
    for domain_name in domain_names:
        if domain_name in domains:
            if res and res != domains[domain_name]:
                print(f"Server {domain_name} is already registered with {res['id']}")
                return None
            res = domains[domain_name]
    return res


def attach_container_to_network(
    docker_client: docker.DockerClient,
    container: Container,
    network: Network | str,
    dry_run=False,
    force=False,
) -> str | None:
    """
    Attach a container to a network
    """
    logger.debug("Try to attach %s to network %s", container.name, network)
    if isinstance(network, str):
        network: Network = docker_client.networks.get(network)
    else:
        network.reload()
    if not force and container.id in network.attrs["Containers"]:
        logger.debug(
            "%s is already attached to network %s", container.name, network.name
        )
        return None
    if dry_run:
        logger.info("Would attach %s to network %s", container.name, network.name)
        return False
    logger.info("Attaching %s to network %s", container.name, network.name)
    network.connect(container)
    return True


def attach_proxy_to_network(
    container: Container, proxy_container: Container, dry_run=False, force=False
) -> str | None:
    """
    Attach the proxy_container to a network of the container
    This is not preferred because we can only guess the correct network
    """
    container_networks = set(container.attrs["NetworkSettings"]["Networks"].keys())
    logger.debug(
        "Try to attach %s to a network of %s %s",
        proxy_container.name,
        container.name,
        container_networks,
    )
    networks = {
        n.name: n
        for n in container.client.networks.list()
        if n.name in container_networks
    }

    def sort_func(n: str):
        if n == "bridge":
            return 0
        if n.endswith("_default"):
            return 1
        return 2

    for net_name in sorted(networks.keys(), key=sort_func):
        net: Network = networks.get(net_name, None)
        if net:
            if not force and proxy_container.id in net.attrs["Containers"]:
                logger.debug(
                    "%s is already attached to network %s",
                    proxy_container.name,
                    net_name,
                )
                return None
            if dry_run:
                logger.info(
                    "Would attach %s to network %s", proxy_container.name, net_name
                )
                return net_name
            logger.info("Attaching %s to network %s", proxy_container.name, net_name)
            net.connect(proxy_container)
            return net_name
    return None


def find_proxy_host(
    docker_client: docker.DockerClient, container: Container, network: str | Network
) -> str | None:
    """
    Check if the container is attached to the proxy network and return its IP or DNS name
    If not attached, return None
    DNS name is preferred if available
    """
    if isinstance(network, Network):
        network = network.name
    container_networks: dict[str, dict] = container.attrs["NetworkSettings"]["Networks"]
    if network := container_networks.get(network, None):
        if network["DNSNames"] and container.name in network["DNSNames"]:
            return container.name
        return network["IPAddress"]
    return None


def check_for_changes(
    nginx_proxy_manager: ApiHandler,
    docker_client: docker.DockerClient,
    letsencrypt_config: dict,
    proxy_network: Network | str,
    proxy_container: Container | str,
    attach_network: str | None = "container",
    proxy_host_defaults=None,
    dry_run=False,
):
    if attach_network:
        if isinstance(proxy_container, str):
            proxy_container = docker_client.containers.get(proxy_container)
        else:
            proxy_container.reload()
        if isinstance(proxy_network, str):
            proxy_network = docker_client.networks.get(proxy_network)
        else:
            proxy_network.reload()
    proxy_host_defaults = proxy_host_defaults or {}
    logger.debug("Looking for changes in container")
    domains = {}
    for host in nginx_proxy_manager.get_proxy_hosts():
        logger.debug("Found host %s", host)
        for domain in host["domain_names"]:
            domains[domain.lower()] = host

    def check_container(container: Container, domains: dict[str, dict]):
        cont_name = container.name
        env_vars = get_env_vars(container)
        labels = get_labels(container)
        virtual_host = labels.get("VIRTUAL_HOST", env_vars.get("VIRTUAL_HOST", None))
        virtual_port = labels.get("VIRTUAL_PORT", env_vars.get("VIRTUAL_PORT", 80))
        if not virtual_host:
            return
        logger.info(
            "Processing container %s as virtual_host: %s", cont_name, virtual_host
        )
        forward_port = int(virtual_port)
        domain_names = [s.strip() for s in virtual_host.split(",")]
        matching_host = get_matching_hosts(domain_names, domains)
        if attach_network == "container":
            if attach_container_to_network(
                docker_client=docker_client,
                container=container,
                network=proxy_network,
                dry_run=dry_run,
            ):
                logger.info(f"Attached {cont_name} to network {proxy_network.name}")
                time.sleep(1)
                container.reload()
            proxy_host = find_proxy_host(
                docker_client=docker_client, container=container, network=proxy_network
            )
        elif attach_network == "proxy":
            if attached_net := attach_proxy_to_network(
                container=container,
                proxy_container=proxy_container,
                dry_run=dry_run,
            ):
                logger.info(
                    "Attached the nginx-proxy-manager container (%s) to the container network %s",
                    proxy_container.name,
                    attached_net,
                )
            proxy_host = find_proxy_host(
                docker_client=docker_client, container=container, network=attached_net
            )
        else:
            proxy_host = find_proxy_host(
                docker_client=docker_client, container=container, network=proxy_network
            )
        if not proxy_host:
            raise NullResource(f"proxy_host for {cont_name} not found")
        if matching_host:
            logger.debug("Found matching host for %s", domain_names)
            nginx_proxy_manager.update_proxy_host(
                host_data=matching_host,
                domain_names=domain_names,
                forward_host=proxy_host,
                forward_port=forward_port,
                letsencrypt_config=letsencrypt_config,
                dry_run=dry_run,
                **proxy_host_defaults,
            )
        else:
            logger.info("Creating new host for %s", domain_names)
            nginx_proxy_manager.create_proxy_host(
                domain_names=domain_names,
                forward_host=proxy_host,
                forward_port=forward_port,
                letsencrypt_config=letsencrypt_config,
                dry_run=dry_run,
                **proxy_host_defaults,
            )

    containers = docker_client.containers.list()
    logger.debug("Checking %d containers", len(containers))
    for container in containers:
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


def get_container_by_label(
    docker_client: docker.DockerClient, label_key: str | dict
) -> Container | None:
    """
    Get a container by its label
    """
    container: Container
    for container in docker_client.containers.list():
        labels = get_labels(container)
        if isinstance(label_key, dict):
            if all(labels.get(key) == val for key, val in label_key.items()):
                return container
        elif isinstance(label_key, str):
            if labels.get(label_key) == "nginx-proxy-manager":
                return container
        else:
            raise ValueError("label_key must be a dict or str")
    return None


def init(config: dict, docker_client: docker.DockerClient, dry_run=False) -> int:
    """
    Initialize the application with the given config
    """
    if not config.get("proxy_container"):
        # Try to find the proxy container
        label_key = config.get("proxy_container_label")
        container = get_container_by_label(docker_client, label_key)
        if not container:
            logger.error("Could not find proxy container by label %s", label_key)
            return -1
        config["proxy_container"] = container
    else:
        try:
            container = docker_client.containers.get(config["proxy_container"])
            config["proxy_container"] = container
            logger.info("Using proxy container %s from config", container.name)
        except NotFound:
            logger.error("Could not find proxy container %s", config["proxy_container"])
            return -1
    if not config.get("own_container"):
        # Try to find own container
        label_key = config.get("own_container_label")
        container = get_container_by_label(docker_client, label_key)
        if not container:
            logger.error("Could not find own container by label %s", label_key)
            return -1
        config["own_container"] = container
    else:
        try:
            container = docker_client.containers.get(config["own_container"])
            config["own_container"] = container
            logger.info("Using own container %s from config", container.name)
        except NotFound:
            logger.error("Could not find own container %s", config["own_container"])
            return -1
    if not config.get("proxy_network"):
        # Try to find the proxy network from the proxy container
        container: Container = config["proxy_container"]
        compose_project = get_labels(container).get("com.docker.compose.project")
        net_name: str
        networks: dict = container.attrs["NetworkSettings"]["Networks"]
        if len(networks) == 1:
            config["proxy_network"] = list(networks.keys())[0]
        if len(networks) > 1:
            for net_name, net in networks.items():
                if compose_project:
                    try:
                        network: Network = docker_client.networks.get(net["NetworkID"])
                        if (
                            network.attrs.get("Labels", {}).get(
                                "com.docker.compose.project"
                            )
                            == compose_project
                        ):
                            config["proxy_network"] = net_name
                            break
                    except NotFound:
                        continue
                elif net_name.removesuffix("_default") in container.name:
                    config["proxy_network"] = net_name
                    break
            else:
                logger.error(
                    "Could not identify proxy network for container %s",
                    container.name,
                )
                return -1
        else:
            logger.error("Proxy container %s has no networks", container.name)
            return -1
    else:
        try:
            _ = docker_client.networks.get(config["proxy_network"])
        except NotFound:
            logger.error("Could not find proxy network %s", config["proxy_network"])
            return -1
        logger.info("Using proxy network %s from config", config["proxy_network"])
    if config.get("attach_self") == "container":
        attach_container_to_network(
            docker_client=docker_client,
            container=config["own_container"],
            network=config["proxy_network"],
            dry_run=dry_run,
        )
    elif config.get("attach_self") == "proxy":
        attach_proxy_to_network(
            container=config["own_container"],
            proxy_container=config["proxy_container"],
            dry_run=dry_run,
        )
    else:
        if (
            not config["own_container"].id
            in config["proxy_network"].attrs["Containers"]
        ):
            logger.error(
                "Own container %s is not attached to proxy network %s",
                config["own_container"].name,
                config["proxy_network"],
            )
            return -1
    proxy_host = find_proxy_host(config["proxy_container"], config["proxy_network"])
    if not proxy_host:
        logger.error(
            "Proxy container %s is not attached to proxy network %s",
            config["proxy_container"].name,
            config["proxy_network"],
        )
        return -1
    if not config["nginx_proxy_manager_url"]:
        config["nginx_proxy_manager_url"] = f"http://{proxy_host}:81/api"
        logger.info(
            "Using nginx proxy manager URL %s",
            config["nginx_proxy_manager_url"],
        )
    return 0


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

    docker_client = docker.from_env()

    init(docker_client=docker_client, config=config, dry_run=args.dry_run)

    nginx_proxy_manager = ApiHandler(
        api_url=config["nginx_proxy_manager_url"],
        user=config["nginx_proxy_manager_user"],
        password=config["nginx_proxy_manager_password"],
        verify_ssl=config["verify_ssl"],
    )

    if args.dry_run:
        logger.info("Running in dry-run mode")
    if args.interval <= 0:
        logger.info("Starting one time check ")
    else:
        logger.info("Starting the check with interval %d sec", args.interval)

    stop_event = threading.Event()

    def interrupt_handler(signum, frame):
        logger.info("Interrupt received, stopping...")
        stop_event.set()

    signal.signal(signal.SIGINT, interrupt_handler)
    while True:
        check_for_changes(
            nginx_proxy_manager=nginx_proxy_manager,
            docker_client=docker_client,
            proxy_network=config["proxy_network"],
            attach_network=config["attach_network"],
            proxy_container=config["proxy_container"],
            letsencrypt_config=config["letsencrypt"],
            proxy_host_defaults=config["proxy_host_defaults"],
            dry_run=args.dry_run,
        )
        if args.interval <= 0:
            break
        stop_event.wait(args.interval)


if __name__ == "__main__":
    main()
