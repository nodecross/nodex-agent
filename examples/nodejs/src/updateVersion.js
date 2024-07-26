import { post } from "./lib/sock.js";

(async () => {
  const payload = {
    message: {
      binary_url: "http://example.com/nodex-agent-1.0.0.zip",
      path: "/tmp",
    },
  };

  const response = await post("/internal/version/update", payload);

  console.log("The response is as follows.\n");
  console.log(response);
})();
