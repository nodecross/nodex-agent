import { post } from "./lib/sock.js";

(async () => {
  const payload = Array.from({ length: 10 }, (_, i) => ({
    key: `test-key${i}`,
    detail: `test-detail${i}`,
    occurred_at: Date.now() + i,
  }));
  const response = await post("/events", payload);

  console.log("The response is as follows.\n");
  console.log(response);
})();
