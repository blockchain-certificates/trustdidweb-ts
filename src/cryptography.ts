import * as ed from '@noble/ed25519';
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';

import { bytesToHex, createDate } from "./utils";
import { base58btc } from "multiformats/bases/base58"
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';
import * as secp256k1 from "@noble/secp256k1";

export const createSigner = (vm: VerificationMethod) => {
  return async (doc: any, challenge: string) => {
    try {
      const proof: any = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: `did:key:${vm.publicKeyMultibase}`,
        created: createDate(),
        proofPurpose: 'authentication',
        challenge
      }
      const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
      const proofHash = createHash('sha256').update(canonicalize(proof)).digest();
      const input = Buffer.concat([dataHash, proofHash]);
      const secretKey = base58btc.decode(vm.secretKeyMultibase!);

      let output;
      if (vm.publicKeyMultibase!.startsWith('zQ3s')) {
        const hashedInput = createHash('sha256').update(bytesToHex(input)).digest();
        output = await secp256k1.signAsync(bytesToHex(hashedInput), bytesToHex(secretKey.slice(2, 34)));
        proof.proofValue = base58btc.encode(output.toCompactRawBytes());console.log(output);
      } else if (vm.publicKeyMultibase!.startsWith('z6Mk')) {
        output = await ed.signAsync(bytesToHex(input), bytesToHex(secretKey.slice(2, 34)));
        proof.proofValue = base58btc.encode(output);
      }
      return {...doc, proof};
    } catch (e: any) {
      console.error(e)
      throw new Error(`Document signing failure: ${e.details}`)
    }
  }
}

export const generateEd25519VerificationMethod = async (purpose: 'authentication' | 'assertionMethod' | 'capabilityInvocation' | 'capabilityDelegation'): Promise<VerificationMethod> => {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const publicKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0xed, 0x01]), pubKey]));
  const secretKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0x80, 0x26]), privKey]));

  return {
    type: purpose,
    publicKeyMultibase,
    secretKeyMultibase
  };
}

export const generateX25519VerificationMethod = async (purpose: 'keyAgreement'): Promise<VerificationMethod> => {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const x25519PubKey = edwardsToMontgomeryPub(pubKey);
  const x25519PrivKey = edwardsToMontgomeryPriv(privKey);
  const publicKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0xec, 0x01]), x25519PubKey]));
  const secretKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0x82, 0x26]), x25519PrivKey]));

  return {
    type: purpose,
    publicKeyMultibase,
    secretKeyMultibase
  }
}
