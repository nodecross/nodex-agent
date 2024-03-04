from sock import post

def main():
    # The endpoint and payload you want to send
    endpoint = "/verify-verifiable-message"
    payload = {
        "message": """{"issuer":{"id":"did:nodex:test:EiDWAZgabmwyviEUcvPMssS_kJT1MUyhDO9iPdfx5dw5Xg"},"issuanceDate":"2024-03-04T17:05:39.042635+00:00","@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"credentialSubject":{"container":{"created_at":"2024-03-04T17:05:39.042635+00:00","destination_did":"did:nodex:test:EiBprXreMiba4loyl3psXm0RsECdtlCiQIjM8G9BtdQplA","message_id":"7cca38ee-77a6-4cfe-b7b4-5c0987fa1627","payload":"{\\"string\\": \\"value\\",\\"number\\": 1,\\"boolean\\": True,\\"array\\": [],\\"map\\": {}}","project_hmac":"b843ea611f2229cd645fdbe92c247c0887e5b2dcbed5f5fa75895bb553eee5dc"}},"proof":{"type":"EcdsaSecp256k1Signature2019","proofPurpose":"authentication","created":"2024-03-04T17:05:39.068522+00:00","verificationMethod":"did:nodex:test:EiDWAZgabmwyviEUcvPMssS_kJT1MUyhDO9iPdfx5dw5Xg#signingKey","jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ.._iTjTfHLg78lJzGxwdFq5aT_b3xfNLaLBYybwD6ck8d34IN2a7gXuHIj-eJtUYzuTowNFAl5DGny8yKQMra7qA","controller":null,"challenge":null,"domain":null}}"""
    }

    # Send the POST request and print the response
    json_response = post(endpoint, payload)
    print(json_response)

if __name__ == "__main__":
    main()

