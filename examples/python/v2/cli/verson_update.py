from sock import post

def main():
    endpoint = "/internal/version/update"
    payload = {
      "binary_url": "https://example.com/nodex-agent-1.0.0.zip",
      "path": "/tmp",
    }

    json_response = post(endpoint, payload)
    print(json_response)

if __name__ == "__main__":
    main()

