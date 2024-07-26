import json
from platform_os import is_windows


if is_windows():
    from request import post
else:
    from sock import post


# PLEASE PASTE BELOW THE RESPONSE FROM "generate_vc_message.py".
message = {
    "issuer": {
        "id": "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD"
    },
    "issuanceDate": "2024-03-22T11:43:47.741035+00:00",
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {
        "container": {
            "created_at": "2024-03-22T11:43:47.741035+00:00",
            "destination_did": "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD",
            "message_id": "d8b8bfbc-88ed-4d93-bfa5-a634e35d104e",
            "payload": '{"message": {"string": '
            '"value", "number": 1, '
            '"boolean": true, "array": '
            '["foo", "bar", "baz"], "map": '
            '{"key": "value"}}}',
            "project_hmac": "fc67f9f5c17ccd44ff3f8e270870c2b04f0980e22766b619a62f7c7ac4c95058",
        }
    },
    "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "proofPurpose": "authentication",
        "created": "2024-03-22T11:43:47.775189+00:00",
        "verificationMethod": "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD#signingKey",
        "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..AnO3rmljCEHhbxvvLKxml8coj-JOwSSczlCxS7zfVBRy11AABM-aFBvwJKP32-VMESZnfF_EH0PZvkJSCAnqOg",
        "controller": None,
        "challenge": None,
        "domain": None,
    },
}


payload = {
    "message": json.dumps(message),
}

json_response = post("/verify-verifiable-message", payload)

print("The response is as follows.\n")
print(json_response)
