import { post } from "./lib/sock.js";

// PLEASE PASTE BELOW THE RESPONSE FROM "generateVcMessage.js".
const messageJson = {
  issuer: {
    id: "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD",
  },
  issuanceDate: "2024-06-12T04:51:05.946956+00:00",
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  type: ["VerifiableCredential"],
  credentialSubject: {
    container: {
      created_at: "2024-06-12T04:51:05.946956+00:00",
      destination_did:
        "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD",
      message_id: "53e769ee-3403-4d73-aedf-7769874c2036",
      payload:
        '{\n    "message": {\n        "string": "value",\n        "number": 1,\n        "boolean": true,\n        "array": [\n            "foo",\n            "bar",\n            "baz"\n        ],\n        "map": {\n            "key": "value"\n        }\n    }\n}',
      project_hmac:
        "9c4aaf3ef92499318effeacf783a38fe5e5ce21cefe04ae4e60c5cacdb13c786",
    },
  },
  proof: {
    type: "EcdsaSecp256k1Signature2019",
    proofPurpose: "authentication",
    created: "2024-06-12T04:51:06.295353+00:00",
    verificationMethod:
      "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD#signingKey",
    jws: "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..jNHYvtT1dhkZiOC-QLE1dlF5eFggnIyn7_LiRK5Yl3x7CcOmT4VWvUSYmg3rHFrRMTcmXqq7ooRMTGItOtIjOw",
    controller: null,
    challenge: null,
    domain: null,
  },
};
(async () => {
  const message = JSON.stringify(messageJson, null, 4);

  const response = await post("/verify-verifiable-message", { message });

  console.log("The response is as follows.\n");
  console.log(response);
})();
