import time
from platform_os import is_windows

if is_windows():
    from request import post
else:
    from sock import post

for _ in range(10000):
    json_response = post(
        "/custom_metrics",
        {
            "key": "test-key",
            "value": 10.52,
            "occurred_at": str(int(time.time())),
        },
    )
    print("The response is as follows.\n")
    print(json_response)
