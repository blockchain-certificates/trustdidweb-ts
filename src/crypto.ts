const crypto =
  typeof globalThis === 'object' && 'crypto' in globalThis && 'subtle' in globalThis.crypto ?
    globalThis.crypto : undefined;

export default crypto;
