from sock import post

def main():
    endpoint = "/internal/version/get"
    json_response = post(endpoint, {})
    print(json_response)

if __name__ == "__main__":
    main()

