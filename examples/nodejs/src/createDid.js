import { post } from "./lib/sock.js";

(async () => {
  const response = await post("/identifiers");

  console.log("The response is as follows.\n");
  console.log(response);
})();
