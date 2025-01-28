import time
from platform_os import is_windows

if is_windows():
    from request import post
else:
    from sock import post

events = [
    {
        "key": "test-key" + str(x + 10),
        "detail": "test-detail" + str(x),
        "occurred_at": int(time.time() * 1000 + x),
    }
    for x in range(10)
]

json_response = post(
    "/events",
    events,
)

print("The response is as follows.\n")
print(json_response)
