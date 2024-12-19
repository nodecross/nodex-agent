import { post } from "./lib/sock.js";

(async () => {
  const payload = Array.from({ length: 10 }, (_, i) => ({
    key: `test-key${i}`,
    value: 10.52 + i,
    occurred_at: Date.now() + i,
  }));
  const response = await post("/custom-metrics", payload);

  console.log("The response is as follows.\n");
  console.log(response);
})();
