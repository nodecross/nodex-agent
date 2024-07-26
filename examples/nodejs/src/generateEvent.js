import { post } from "./lib/sock.js";

(async () => {
  const payload = {
    key: "test-key",
    detail: "test-detail",
    occurred_at: String(Math.floor(Date.now() / 1000)),
  };
  const response = await post("/events", payload);

  console.log("The response is as follows.\n");
  console.log(response);
})();
