import { resolveDID } from '../method';
import storePath from "../../dev/constant/storePath";

export const getLatestDIDDoc = async ({params: {id, isTest = false}, set}: {params: {id: string; isTest: boolean}; set: any;}) => {
  console.log(`Resolving ${id}...`);
  // TODO: actually set isTest somewhere so that it gets consumed
  const path = isTest ? './test/logs' : storePath;
  try {
    const didLog = await Bun.file(`${path}/${id}/did.jsonl`).text();
    // console.log(didLog)
    // const logLine: string = '[{"op":"replace","path":"/proof/proofValue","value":"z128ss1..."}]';
    const logEntries: DIDLog = didLog.trim().split('\n').map(l => JSON.parse(l));
    const {did, doc, meta} = await resolveDID(logEntries);
    return {doc, meta};
  } catch (e) {
    console.error(e)
    throw new Error(`Failed to resolve DID`);
  }
}
