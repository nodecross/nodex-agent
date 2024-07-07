from sock import post
import time


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
