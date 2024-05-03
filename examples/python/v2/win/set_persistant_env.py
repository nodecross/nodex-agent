import subprocess
import os

def set_persistent_env_var(name, value):
    subprocess.run(['setx', name, f'"{value}"'], check=True)

def update_env_var(name, value):
    os.environ[name] = value

env_vars = {
    "NODEX_DID_HTTP_ENDPOINT": "https://did.nodecross.io",
    "NODEX_DID_ATTACHMENT_LINK": "https://did.getnodex.io",
    "NODEX_HUB_HTTP_ENDPOINT": "http://localhost:8000",
    "NODEX_SERVER_PORT": "3333"
}
for env_name, env_value in env_vars.items():
    update_env_var(env_name, env_value)
    set_persistent_env_var(env_name, env_value)
