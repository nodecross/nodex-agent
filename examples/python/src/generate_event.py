import time
from platform_os import is_windows

if is_windows():
    from request import post
else:
    from sock import post

json_response = post(
    "/events",
    {
        "key": "test-key",
        "detail": "test-detail",
        "occurred_at": str(int(time.time())),
    },
)

print("The response is as follows.\n")
print(json_response)
