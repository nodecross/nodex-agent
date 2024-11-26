import { post } from "./lib/sock.js";

(async () => {
  const payload = {
    key: "test-key",
    detail: "test-detail",
    occurred_at: Date.now(),
  };
  const response = await post("/events", payload);

  console.log("The response is as follows.\n");
  console.log(response);
})();
