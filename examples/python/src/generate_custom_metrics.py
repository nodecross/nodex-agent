import time
from platform_os import is_windows

if is_windows():
    from request import post
else:
    from sock import post

metrics = [
    {
        "key": "test-key" + str(x),
        "value": 10.52 + x,
        "occurred_at": int(time.time() * 1000 + x),
    }
    for x in range(10)
]


json_response = post("/custom-metrics", metrics)

print("The response is as follows.\n")
print(json_response)
