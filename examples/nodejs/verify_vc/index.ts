import * as os from 'os'
import * as path from 'path'
import axios from 'axios'

(async () => {
    const response = await axios.post('http:/localhost/internal/verifiable-credentials/verify', {
        message: JSON.parse('{"@context":["https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"container":{"array":[],"boolean":true,"map":{},"number":1,"string":"value"}},"issuanceDate":"2022-12-20T16:21:26.869544+00:00","issuer":{"id":"did:unid:test:EiD_ZSrS4E4FZruAIJnMt1KjvH1HvwCRYdnIzYpQr4vsuQ"},"proof":{"challenge":null,"controller":null,"created":"2022-12-20T16:21:26.869571+00:00","domain":null,"jws":"eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..lB5u5Hn4QT43JSHQO7oI7D7u8Iartt9ciH8Lf5OeSnpL2wYNSMWDd57yhIDO-pSn43qNrApxnSAeXo8XywXALQ","proofPurpose":"authentication","type":"EcdsaSecp256k1Signature2019","verificationMethod":"did:unid:test:EiD_ZSrS4E4FZruAIJnMt1KjvH1HvwCRYdnIzYpQr4vsuQ#signingKey"},"type":["VerifiableCredential"]}')
    }, {
        socketPath: path.join(os.homedir(), '.unid/run/unid.sock'),
        headers: {
            'Content-Type': 'application/json'
        }
    })

    console.log(JSON.stringify(response.data, null, 4))
})()
