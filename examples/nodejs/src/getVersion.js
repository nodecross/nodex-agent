import { get } from "./lib/sock.js";

(async () => {
  const response = await get("/internal/version/get");

  console.log("The response is as follows.\n");
  console.log(response);
})();
