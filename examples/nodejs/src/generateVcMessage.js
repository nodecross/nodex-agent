import { post } from "./lib/sock.js";

// PLEASE WRITE destination_did, messageJson, AND operation_tag.
const destination_did =
  "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD";
const messageJson = {
  message: {
    string: "value",
    number: 1,
    boolean: true,
    array: ["foo", "bar", "baz"],
    map: { key: "value" },
  },
};
const operation_tag = "test-operation-tag";

(async () => {
  const message = JSON.stringify(messageJson, null, 4);
  const response = await post("/create-verifiable-message", {
    destination_did,
    message,
    operation_tag,
  });

  console.log('\nPlease paste below to "verifyVcMessage.js".\n');
  console.log(response);
})();
