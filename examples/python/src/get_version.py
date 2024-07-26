from sock import get


json_response = get("/internal/version/get")

print("The response is as follows.\n")
print(json_response)
