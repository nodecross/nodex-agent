import subprocess
import os
import pprint
import sys
from platform_os import is_windows


def set_persistent_env_var(name, value):
    subprocess.run(['setx', name, value], check=True)

def update_env_var(name, value):
    os.environ[name] = value

if not is_windows():
    pprint.pprint("This functionality is only supported on Windows.")
    sys.exit(1)

env_vars = {
    "NODEX_DID_HTTP_ENDPOINT": "https://did.nodecross.io",
    "NODEX_DID_ATTACHMENT_LINK": "https://did.getnodex.io",
    "NODEX_HUB_HTTP_ENDPOINT": "http://http.hub.nodecross.io",
    "NODEX_SERVER_PORT": "3000"
}
for env_name, env_value in env_vars.items():
    update_env_var(env_name, env_value)
    set_persistent_env_var(env_name, env_value)
