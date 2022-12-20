import * as os from 'os'
import * as path from 'path'
import axios from 'axios'

(async () => {
    const response = await axios.get('http:/localhost/identifiers/did:unid:test:EiD_ZSrS4E4FZruAIJnMt1KjvH1HvwCRYdnIzYpQr4vsuQ', {
        socketPath: path.join(os.homedir(), '.unid/run/unid.sock'),
        headers: {
            'Content-Type': 'application/json'
        }
    })

    console.log(JSON.stringify(response.data, null, 4))
})()
