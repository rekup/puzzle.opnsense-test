"""
Utils to parse and validate config from env vars
"""

import os
import sys
import traceback
from typing import Tuple
from ipaddress import ip_address, IPv4Address, IPv6Address
from base_logger import base_logger


def parse_valid_ips(env_var: str, default_value: str = "127.0.0.1") -> Tuple:
    """
    Parses the environment variable containing the valid ip addresses.
    If the var is not defined or contains invalid content, the script exits
    :return: Tuple: ip addresses
    """
    addresses = os.environ.get(env_var, default_value)
    try:
        assert addresses is not None, f"env var {env_var} is not set"
        assert addresses != "", f"env var {env_var} can't be empty"
        address_list = addresses.split(" ")
        assert len(address_list) > 0
        for address in address_list:
            assert isinstance(ip_address(address), (IPv4Address, IPv6Address))

    except (AssertionError, ValueError) as exception:
        base_logger.critical("Unable to parse %s env var", env_var)
        base_logger.critical(str(exception))
    except Exception:
        base_logger.critical("Unhandled exception during env var parsing")
        for line in traceback.format_exc().splitlines():
            base_logger.critical(line)
    else:
        return tuple(address_list)

    base_logger.critical(
        "This is a configuration error. Check %s env var and try again", env_var
    )
    sys.exit(1)


def parse_listen_address(env_var: str, default_value: str = "127.0.0.1") -> str:
    """
    Parses the env var containing a interface address
    :return: str: The ip address to listen on
    """
    address = os.environ.get(env_var, default_value)
    try:
        assert address is not None, f"env var {env_var} is not set"
        assert address != "", f"env var {env_var} can't be empty"
        assert isinstance(ip_address(address), (IPv4Address, IPv6Address))

    except (AssertionError, ValueError) as exception:
        base_logger.critical("Unable to parse %s env var", env_var)
        base_logger.critical(str(exception))
    except Exception:
        base_logger.critical("Unhandled exception during env var parsing")
        for line in traceback.format_exc().splitlines():
            base_logger.critical(line)
    else:
        return str(address)

    base_logger.critical(
        "This is a configuration error. Check %s env var and try again", env_var
    )
    sys.exit(1)


def parse_listen_port(env_var: str, default_value: str = "8080") -> int:
    """
    Parses the env var containing a port number
    :return: ip_address: The ip address to listen on
    """

    try:
        port = int(os.environ.get(env_var, default_value))
        assert 0 <= port <= 65536, f"Port {env_var} must be between 0 and 65536"
    except (AssertionError, ValueError) as exception:
        base_logger.critical("Unable to parse %s env var", env_var)
        base_logger.critical(str(exception))
    except Exception:
        base_logger.critical("Unhandled exception during env var parsing")
        for line in traceback.format_exc().splitlines():
            base_logger.critical(line)
    else:
        return port

    base_logger.critical(
        "This is a configuration error. Check %s env var and try again", env_var
    )
    sys.exit(1)
