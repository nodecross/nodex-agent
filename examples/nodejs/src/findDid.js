import { get } from "./lib/sock.js";

// PLEASE WRITE destination_did
const destination_did =
  "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD";

(async () => {
  const response = await get(`/identifiers/${destination_did}`);

  console.log("The response is as follows.\n");
  console.log(response);
})();
