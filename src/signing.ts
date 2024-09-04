import * as ed from '@noble/ed25519';
import * as secp256k1 from '@noble/secp256k1';
import { bytesToHex, createDate } from "./utils";
import { base58btc } from "multiformats/bases/base58"
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const createSigner = (vm: VerificationMethod) => {
  return async (doc: any, challenge: string) => {
    console.log('verification method', vm);
    console.log('private key', base58btc.decode(vm.secretKeyMultibase!));
    console.log('public key', base58btc.decode(vm.publicKeyMultibase!));
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

      console.log('signing input', input, 'as hex', bytesToHex(input));

      let output;
      if (vm.publicKeyMultibase!.startsWith('zQ3s')) {
        const hashedInput = createHash('sha256').update(bytesToHex(input)).digest();
        console.log('signing hash', bytesToHex(hashedInput));
        console.log('private key hex', bytesToHex(secretKey.slice(2, 34)));
        console.log('public key hex', bytesToHex(base58btc.decode(vm.publicKeyMultibase!).slice(2)));
        output = await secp256k1.signAsync(bytesToHex(hashedInput), bytesToHex(secretKey.slice(2, 34)));
        proof.proofValue = base58btc.encode(output.toCompactRawBytes());
        console.log(output);
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
