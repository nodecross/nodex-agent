import json
from platform_os import is_windows


if is_windows():
    from request import post
else:
    from sock import post


payload = {
    "message": {
        "binary_url": "https://example.com/nodex-agent-1.0.0.zip",
        "path": "/tmp",
    }
}

json_response = post("/internal/version/update", payload)

print("The response is as follows.\n")
print(json_response)
