import os
import requests_unixsocket
import json
import urllib.parse
import sys


# Create a session that can make requests to Unix sockets
session = requests_unixsocket.Session()

default_path = os.path.join(os.path.expanduser("~"), ".nodex/run/nodex.sock")
path_by_installed_deb = "/home/nodex/.nodex/run/nodex.sock"
sock_path = (
    path_by_installed_deb
    if os.path.exists(path_by_installed_deb)
    else default_path
)

# Construct the base URL using the Unix socket path
base = f'http+unix://{urllib.parse.quote(sock_path, safe="")}'


def call(method, path, payload):
    url = f"{base}:{path}"
    print("Now Requesting...")
    print(f"- Method: {method.upper()}")
    print(f"- URL: {urllib.parse.unquote(url)}\n")

    if method == "get":
        response = session.get(url)
    elif method == "post":
        response = session.post(url, json=payload)
    else:
        raise ValueError(f"Unsupported method: {method}")

    if response.status_code != 200 and response.status_code != 204:
        print(
            f"{response.status_code} {response.reason}\n"
            f"body : {json.dumps(response.json(), indent=4)}"
        )
        sys.exit(1)

    elif response.status_code == 204:
        return "No content"
    else:
        return json.dumps(response.json(), indent=4)


def get(path):
    return call("get", path, None)


def post(path, payload={}):
    return call("post", path, payload)
