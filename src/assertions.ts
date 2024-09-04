import * as ed from '@noble/ed25519';
import * as secp256k1 from '@noble/secp256k1';
import { base58btc } from "multiformats/bases/base58";
import { bytesToHex, deriveHash } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const keyIsAuthorized = (verificationMethod: string, updateKeys: string[]) => {
  return updateKeys.includes(verificationMethod);
}

const PREFIXES = {
  'secp256k1': 'zQ3s',
  'ed25519': 'z6Mk'
}

export const documentStateIsValid = async (doc: any, proofs: any[], updateKeys: string[]) => {
  let i = 0;
  while(i < proofs.length) {
    const proof = proofs[i];
    console.log('vm', proof.verificationMethod.split('#')[0], 'updateKeys', updateKeys);
    if (!keyIsAuthorized(proof.verificationMethod.split('#')[0], updateKeys)) {
      throw new Error(`key ${proof.verificationMethod} is not authorized to update.`)
    }
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'authentication') {
      throw new Error(`Unknown proof purpose] ${proof.proofPurpose}`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }
    const publicKey = base58btc.decode(proof.verificationMethod.split('did:key:')[1].split('#')[0]);
    const {proofValue, ...restProof} = proof;
    const sig = base58btc.decode(proofValue);
    const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
    const proofHash = createHash('sha256').update(canonicalize(restProof)).digest();
    const input = Buffer.concat([dataHash, proofHash]);

    const multikeyPrefix = proof.verificationMethod.split('did:key:')[1].split('#')[0].slice(0, 4);
    console.log(multikeyPrefix, proof.verificationMethod.split('did:key:')[1].split('#')[0]);
    console.log('sig', sig);

    let verified = false;
    if (multikeyPrefix === PREFIXES.ed25519) {
      verified = await ed.verifyAsync(
        bytesToHex(sig),
        bytesToHex(input),
        bytesToHex(publicKey.slice(2))
      );
    } else if (multikeyPrefix === PREFIXES.secp256k1) {
      const hashedInput = createHash('sha256').update(bytesToHex(input)).digest();
      console.log('verifying hash', bytesToHex(hashedInput));
      console.log('public key', publicKey.slice(2));
      verified = secp256k1.verify(
        bytesToHex(sig),
        bytesToHex(hashedInput),
        bytesToHex(publicKey.slice(2))
      )
    }
    if (!verified) {
      return false;
    }
    i++;
  }
  return true;
}

export const newKeysAreValid = (updateKeys: string[], previousNextKeyHashes: string[], nextKeyHashes: string[], previousPrerotate: boolean, prerotate: boolean) => {
  if (prerotate && nextKeyHashes.length === 0) {
    throw new Error(`nextKeyHashes are required if prerotation enabled`);
  }
  if(previousPrerotate) {
    const inNextKeyHashes = updateKeys.reduce((result, key) => {
      const hashedKey = deriveHash(key);
      return result && previousNextKeyHashes.includes(hashedKey);
    }, true);
    if (!inNextKeyHashes) {
      throw new Error(`invalid updateKeys ${updateKeys}`);
    }
  }
  return true;
}
