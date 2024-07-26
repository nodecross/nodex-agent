import os
import json
import requests
import urllib.parse
from dotenv import load_dotenv
import os


dotenv_path = os.path.join(os.path.dirname(__file__), '../../../../', '.env')
load_dotenv(dotenv_path)
port = os.getenv('NODEX_SERVER_PORT')
if not port:
    raise Exception("NODEX_SERVER_PORT is missing from the environment variables.")

# Construct the base URL using the Unix socket path
base = f'http://localhost:{port}'


def call(method, path, payload):
    url = f"{base}{path}"
    print("Now Requesting...")
    print(f"- Method: {method.upper()}")
    print(f"- URL: {urllib.parse.unquote(url)}\n")

    try:
        if method == "get":
            response = requests.get(url)
        elif method == "post":
            response = requests.post(url, json=payload)
        else:
            raise ValueError(f"Unsupported method: {method}")
        # Raises stored HTTPError, if one occurred.
        response.raise_for_status()
        return json.dumps(response.json(), indent=4)
    except Exception as e:
        return (
            f"{e.response.status_code} "
            f"{e.response.reason} "
            f"{e.response.text}"
        )


def get(path):
    return call("get", path, None)


def post(path, payload={}):
    return call("post", path, payload)
