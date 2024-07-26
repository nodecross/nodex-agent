from platform_os import is_windows


if is_windows():
    from request import post
else:
    from sock import post


json_response = post("/identifiers")

print("The response is as follows.\n")
print(json_response)
