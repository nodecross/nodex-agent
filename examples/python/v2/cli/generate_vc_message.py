from sock import post

def main():
    # The endpoint and payload you want to send
    endpoint = "/create-verifiable-message"
    payload = {
        "destination_did": "did:nodex:test:EiBprXreMiba4loyl3psXm0RsECdtlCiQIjM8G9BtdQplA",
        "message": """{"string": "value","number": 1,"boolean": True,"array": [],"map": {}}""",
        "operation_tag": "test-operation-tag",
    }

    # Send the POST request and print the response
    json_response = post(endpoint, payload)
    print(json_response)

if __name__ == "__main__":
    main()

