from sock import get

def main():
    endpoint = "/identifiers/did:nodex:test:EiD_ZSrS4E4FZruAIJnMt1KjvH1HvwCRYdnIzYpQr4vsuQ"
    json_response = get(endpoint)
    print(json_response)

if __name__ == "__main__":
    main()

