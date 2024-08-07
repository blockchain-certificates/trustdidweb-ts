import { createSigner, createDID } from '../src/index';
import storePath from "./constant/storePath";
import fs from "node:fs";

const availableKeys = {
  secp256k1: [
    {
      "publicKeyMultibase": "zQ3shvX9Dd7cAG7ZcJN4d9DksshpVYSGpqEyrLjopoGpk97CR",
      "secretKeyMultibase": "z42sPkL6ZTCeUKfTZejXUoAXqEyu9hCvKXeeerferF7aN9Bw"
    }
  ]
}

const currentAuthKey = {type: 'authentication', ...availableKeys.secp256k1[0]}

function saveDID (doc: any, log: any, version: number) {
  const saveDocPath = `${storePath}/${doc.id}/did.json`;
  const saveLogPath = `${storePath}/${doc.id}/did.jsonl`;

  fs.mkdirSync(`${storePath}/${doc.id}`, {recursive: true});
  fs.writeFileSync(saveDocPath, JSON.stringify(doc, null, 2));
  fs.writeFileSync(saveLogPath, JSON.stringify(log.shift()) + '\n');
  console.log('DID saved');
}

export async function initDID () {
  const did = await createDID({
    domain: 'blockcerts.org',
    signer: createSigner(currentAuthKey!),
    updateKeys: [`did:key:${currentAuthKey!.publicKeyMultibase}`],
    verificationMethods: [
      currentAuthKey!,
      // {type: 'assertionMethod', ...availableKeys.secp256k1[0]},
    ]});

  saveDID(did.doc, did.log, 1);

  console.log(JSON.stringify(did, null, 2));
  return did.doc.id;
}
