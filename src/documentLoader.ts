import didContext from 'did-context';
import ed25519Ctx from 'ed25519-signature-2020-context';
import secCtx from '@digitalbazaar/security-context';
import multikeyContext from '@digitalbazaar/multikey-context';
import dataIntegrityCtx from '@digitalbazaar/data-integrity-context';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';

export const jdl = new JsonLdDocumentLoader();
  
jdl.addStatic(
  didContext.constants.DID_CONTEXT_URL,
  didContext.contexts.get(didContext.constants.DID_CONTEXT_URL)
)
jdl.addStatic(ed25519Ctx.CONTEXT_URL, ed25519Ctx.CONTEXT);
jdl.addStatic(secCtx.SECURITY_CONTEXT_V1_URL, secCtx.contexts.get(secCtx.SECURITY_CONTEXT_V1_URL));
jdl.addStatic(secCtx.SECURITY_CONTEXT_V2_URL, secCtx.contexts.get(secCtx.SECURITY_CONTEXT_V2_URL));
jdl.addStatic(dataIntegrityCtx.CONTEXT_URL, dataIntegrityCtx.CONTEXT);
jdl.addStatic(multikeyContext.CONTEXT_URL, multikeyContext.CONTEXT);
jdl.addStatic(`https://identity.foundation/linked-vp/contexts/v1`, {
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "LinkedVerifiablePresentation": "https://identity.foundation/linked-vp/contexts/v1#LinkedVerifiablePresentation"
    }
  ]
});
jdl.addStatic(`https://didcomm.org/messaging/v2`, {
  "@context":{
     "@version":1.1,
     "@protected":true,
     "DIDCommMessaging":"https://didcomm.org/messaging/v2/#DIDCommMessaging",
     "accept":"https://didcomm.org/messaging/v2/#accept",
     "routingKeys":"https://didcomm.org/messaging/v2/#routingKeys",
     "uri":"https://didcomm.org/messaging/v2/#uri",
  }
})

export const documentLoader = jdl.build();