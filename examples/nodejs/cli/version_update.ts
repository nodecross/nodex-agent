import { post } from './sock.js'

(async () => {
  const json = await post('/internal/version/update', {
    message: {
      "binary_url": "https://example.com/nodex-agent-1.0.0.zip",
      "path": "/tmp",
    }
  })

  console.log(json)
})()
