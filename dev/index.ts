import {createSigner, createDID, generateEd25519VerificationMethod} from '../src/index';
import storePath from "./constant/storePath";
import fs from "node:fs";

const availableKeys = {
  secp256k1: [
    {
      // BTC Mainnet
      "publicKeyMultibase": "zQ3shw8MAkueKou9VhRyX1v2hDQ2WENWVQNkg6ifhn8DG1gQW",
      "secretKeyMultibase": "z3vLe1VYhhknE9VgKWKwr4paApJvY2jrVBe71vU3SmeyvgND"
    },
    {
      // BTC Testnet & ETH
      publicKeyMultibase: 'zQ3shvX9Dd7cAG7ZcJN4d9DksshpVYSGpqEyrLjopoGpk97CR',
      secretKeyMultibase: 'z3vLXeaq5rH3HKuwaJLmvgRM2hD3RvF9tCuXrQZyg2kPTPgd',
    }
  ]
}

async function getAuthKeys () {
  const ed25519DidKey = await generateEd25519VerificationMethod('authentication');
  return [
    ed25519DidKey,
    {type: 'assertionMethod', ...availableKeys.secp256k1[0]},
    {type: 'assertionMethod', ...availableKeys.secp256k1[1]}
  ]
}

function saveDID (doc: any, log: any, version: number) {
  const saveDocPath = `${storePath}/${doc.id}/did.json`;
  const saveLogPath = `${storePath}/${doc.id}/did.jsonl`;

  fs.mkdirSync(`${storePath}/${doc.id}`, {recursive: true});
  fs.writeFileSync(saveDocPath, JSON.stringify(doc, null, 2));
  fs.writeFileSync(saveLogPath, JSON.stringify(log.shift()) + '\n');
  console.log('DID saved');
}

export async function initDID () {
  const currentAuthKey = await getAuthKeys();
  console.log(currentAuthKey);
  const did = await createDID({
    domain: 'blockcerts.org',
    signer: createSigner(currentAuthKey[0]!),
    updateKeys: [currentAuthKey[0]!.publicKeyMultibase],
    verificationMethods: [
      ...currentAuthKey!
    ],
    service: [
      {
        id: '#service-1',
        type: 'IssuerProfile',
        serviceEndpoint: 'https://www.blockcerts.org/samples/3.0/issuer-blockcerts.json'
      }
    ]
  });

  saveDID(did.doc, did.log, 1);

  console.log(JSON.stringify(did, null, 2));
  return did.doc.id;
}
