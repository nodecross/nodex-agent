import json
from platform_os import is_windows


if is_windows():
    from request import get
else:
    from sock import get


json_response = get("/internal/version/get")

print("The response is as follows.\n")
print(json_response)
