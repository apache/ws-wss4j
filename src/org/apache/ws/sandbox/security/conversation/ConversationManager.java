/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.security.conversation;

import org.apache.axis.components.logger.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org.apache.ws.security.message.EnvelopeIdResolver;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import java.util.Vector;

/**
 * This class helps handlers to carry on conversation.
 * <p/>
 * It performes functionalities
 * 1) Adding derived Keys
 * 2) Signing using derived keys
 * 3) Encrypting using derive keys
 * <p/>
 * Actually the class is the collection of methods that are useful
 * for carrying out conversation.
 *
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 */
public class ConversationManager {

    private static Log log =
            LogFactory.getLog(ConversationManager.class.getName());

    private int generation = 0;
    protected String canonAlgo = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    /**
      * Adds Derived key tokens to the header of the SOAP message, given the
      * following parameters.
      * @param doc
      * @param uuid
      * @param dkcbHandler
      * @param stRef2Base -SecurityTOkenReference to the token, from which the derived
      *                    key is derived from
      * @return
      * @throws ConversationException
      */
     public DerivedKeyInfo createDerivedKeyToken(Document doc,
                                             String uuid,
                                             DerivedKeyCallbackHandler dkcbHandler,SecurityTokenReference stRef2Base, int keyLen )
            throws ConversationException {
        String genID = ConversationUtil.genericID();
        
        /*
         * This metod is 4-step procedure. 
         */
         
        // step 1 : Creating wsse:Reference to DerivedKeyToken
        Reference ref = new Reference(WSSConfig.getDefaultWSConfig(), doc);
        ref.setURI("#" + genID);
        ref.setValueType("http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk");
        SecurityTokenReference stRef = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(), doc);
        stRef.setReference(ref);

        WSSecurityUtil.setNamespace(stRef.getElement(),
                WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);

        // step 2 :Create the DerriveToken
        DerivedKeyToken dtoken = new DerivedKeyToken(doc);
		if(stRef2Base != null){
			dtoken.setSecuityTokenReference(doc, stRef2Base);
		}
        dtoken.setLabel(doc, "WS-SecureConversationWS-SecureConversation");
        dtoken.setNonce(doc, ConversationUtil.generateNonce(128));
        dtoken.setID(genID);
		//System.out.println("Fix me here ....");
		
		if(keyLen!=-1){
		   dtoken.setLength(doc,keyLen);
		}
        
        //step 3 :add the derived key token infomation into the dkcbHandler
        DerivedKeyInfo dkInfo = null;
        try {
            dkInfo = new DerivedKeyInfo(dtoken);
            dkInfo.setSecTokRef2DkToken(stRef);
            dkcbHandler.addDerivedKey(uuid, dkInfo);
        } catch (WSSecurityException e) {
            e.printStackTrace();
            throw new ConversationException("ConversationManager:: Cannot add Derived key token to the envelope");
        }

               
		return dkInfo;

    }
    
    
    public void addDkToken(Document doc, DerivedKeyInfo info){
    	  DerivedKeyTokenAdder adder = new DerivedKeyTokenAdder();
    	  adder.build(doc, info.getDkTok());
    }		  

    /**
     * Manages derived key encryption.
     *
     * @param encUser
     * @param actor
     * @param mu
     * @param doc
     * @param secRef - SecurityTokenReference pointing to the derived Key
     * @param dkcbHandler
     * @throws ConversationException
     */
    public void performDK_ENCR(String encUser,
                               String actor,
                               boolean mu,
                               Document doc,
                               SecurityTokenReference secRef,
                               DerivedKeyCallbackHandler dkcbHandler, Vector parts,
                               String symAlgo)
            throws ConversationException {
        WSEncryptBody wsEncrypt = new WSEncryptBody(actor, mu);

        /*
         * Here we want to add a wsse:SecurityTokenReference element into <KeyInfo>.
         * Rest is as same as EMBEDDED_KEYNAME , i.e. we want to encrypt the message
         * using a symmetric key and the result would be an <EncryptedData> element.
         * Steps are
         * step 1: Adding SecurityTokenReference pointing to DkToken
         * step 2: Adding the key into wsEncrypt
         * step 3: Setting the user.
         */
        wsEncrypt.setKeyIdentifierType(WSConstants.EMBED_SECURITY_TOKEN_REF);
		
        /*
         * step 1: Adding SecurityTokenReference pointing to DkToken.
         */
        wsEncrypt.setSecurityTokenReference(secRef);

        /*
         * step 2: Generating the key, and setting it in the the wsEncrypt
         */
        WSPasswordCallback pwCb =
                new WSPasswordCallback(encUser, WSPasswordCallback.UNKNOWN);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = (Callback) pwCb;

        try {
            dkcbHandler.handle(callbacks);
        } catch (java.lang.Exception e) {
            e.printStackTrace();
            throw new ConversationException("ConversationManager :: PasswordCallback failed");
        }

        wsEncrypt.setKey(pwCb.getKey());
        /*
         * step 3: set the user.
         */
        wsEncrypt.setUserInfo(encUser);
        
        /*
         * step 4 : Setting encryption parts
         */
         wsEncrypt.setParts(parts);  
        
         wsEncrypt.setSymmetricEncAlgorithm(symAlgo);
         
        try {
            wsEncrypt.build(doc, null);
        } catch (WSSecurityException e) {
        	e.printStackTrace();
            throw new ConversationException("ConversationManager :: Encryption: error during message processing");
        }

    }

    /**
     * Manages derived key signature.
     *
     * @param doc
     * @param dkcbHandler
     * @param uuid
     * @param dkSigInfo
     * @throws ConversationException
     */
    public void performDK_Sign(Document doc,
                               DerivedKeyCallbackHandler dkcbHandler,
                               String uuid,
                               DerivedKeyInfo dkSigInfo, Vector parts)
            throws ConversationException {
        //            Signing....
        //        HMAC_SignVerify sign = new HMAC_SignVerify();
        String sigAlgo = XMLSignature.ALGO_ID_MAC_HMAC_SHA1;

        String sigUser =
                ConversationUtil.generateIdentifier(uuid, dkSigInfo.getId());
        System.out.println("Signature user is ::"+sigUser);
        WSPasswordCallback pwCb =
                new WSPasswordCallback(sigUser, WSPasswordCallback.UNKNOWN);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = (Callback) pwCb;

        try {
            dkcbHandler.handle(callbacks);
        } catch (java.lang.Exception e) {
            throw new ConversationException("ConversationManager :: Password callback failed");
        }
        try {
            Reference ref = dkSigInfo.getSecTokRef2DkToken().getReference();
            this.build(doc, ref, pwCb.getKey(), parts);
        } catch (WSSecurityException e1) {
            e1.printStackTrace();
            throw new ConversationException("ConversationManager :: Error performing signature.");
        }

    }

    /**
     * The method is coded such that it can be plugged into WSSignEnvelope.
     * Performs HMAC_SHA1 signature.
     * needed.
     *
     * @param doc
     * @param ref
     * @param sk
     * @param parts
     * @return
     * @throws WSSecurityException
     */
    public Document build(Document doc, Reference ref, byte[] sk, Vector parts)
            throws WSSecurityException {
        boolean doDebug = log.isDebugEnabled();

        if (doDebug) {
            log.debug("Beginning signing...");
        }

        if (ref == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "Invalid Data",
                    new Object[]{"For symmeric key signatures - Reference object must be provided"});
        }

        if (sk == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "Invalid Data",
                    new Object[]{"For symmeric key signatures - Reference object must be provided"});
        }
        String sigAlgo = XMLSignature.ALGO_ID_MAC_HMAC_SHA1;
        log.debug("Key is "+new String(sk));

        SecretKey sharedKey = new SecretKeySpec(sk, sigAlgo);

        //TODO :: Check for the characteristics (eg: legnth of the key) of the key if it applies.

        /*
         * Gather some info about the document to process and store it for
         * retrival
         */
        WSDocInfo wsDocInfo = new WSDocInfo(doc.hashCode());
        Element envelope = doc.getDocumentElement();
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);
        Element securityHeader =
                WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(),
                        doc,
                        doc.getDocumentElement(),
                        true);

        XMLSignature sig = null;
        try {
            sig = new XMLSignature(doc, null, sigAlgo, canonAlgo);
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig");
        }

        KeyInfo info = sig.getKeyInfo();
        String keyInfoUri = "KeyId-" + info.hashCode();
        info.setId(keyInfoUri);

        SecurityTokenReference secRef = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(), doc);
        String strUri = "STRId-" + secRef.hashCode();
        secRef.setID(strUri);

        if (parts == null) {
            parts = new Vector();
            WSEncryptionPart encP =
                    new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(),
                            soapConstants.getEnvelopeURI(),
                            "Content");
            parts.add(encP);
        }

        /*
         * The below "for" loop (which perform transforms) is
         * copied from 
         *        build(Document doc, Crypto crypto) method in
         *            org.apache.ws.security.message.WSEncryptBody.java                  
         */

        Transforms transforms = null;

        for (int part = 0; part < parts.size(); part++) {
            WSEncryptionPart encPart = (WSEncryptionPart) parts.get(part);
            String elemName = encPart.getName();
            String nmSpace = encPart.getNamespace();

            /*
             * Set up the elements to sign. There are two resevered element
             * names: "Token" and "STRTransform" "Token": Setup the Signature
             * to either sign the information that points to the security token
             * or the token itself. If its a direct reference sign the token,
             * otherwise sign the KeyInfo Element. "STRTransform": Setup the
             * ds:Reference to use STR Transform
             *
             */
            try {
                if (elemName.equals("Token")) {
                    transforms = new Transforms(doc);
                    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    sig.addDocument("#" + keyInfoUri, transforms);
                } else if (elemName.equals("STRTransform")) { // STRTransform
                    Element ctx = createSTRParameter(doc);
                    transforms = new Transforms(doc);
                    transforms.addTransform(STRTransform.implementedTransformURI,
                            ctx);
                    sig.addDocument("#" + strUri, transforms);
                } else {
                    Element body =
                            (Element) WSSecurityUtil.findElement(envelope,
                                    elemName,
                                    nmSpace);
                    if (body == null) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                "noEncElement",
                                new Object[]{nmSpace + ", " + elemName});
                    }
                    transforms = new Transforms(doc);
                    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    sig.addDocument("#" + setWsuId(body), transforms);
                }
            } catch (TransformationException e1) {
                throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                        "noXMLSig",
                        null,
                        e1);
            } catch (XMLSignatureException e1) {
                throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                        "noXMLSig",
                        null,
                        e1);
            }
        }

        sig.addResourceResolver(EnvelopeIdResolver.getInstance(WSSConfig.getDefaultWSConfig()));

        /*
         * Prepending order
         * -Append the signature element.
         * -Apped the KeyInfo element
         */
        WSSecurityUtil.appendChildElement(doc,
                securityHeader,
                sig.getElement());

        /*
         * Put the "Reference object" into secRef in KeyInfo
         */
        secRef.setReference(ref);

        info.addUnknownElement(secRef.getElement());

        try {
            sig.sign(sharedKey);
        } catch (XMLSignatureException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    null,
                    null,
                    e1);
        }

        if (doDebug) {
            log.debug("Signing complete.");
        }
        return (doc);

    }

    /*
     * Extracted from org.apache.ws.security.message.WSSignEnvelope.java
     */
    private Element createSTRParameter(Document doc) {
        Element transformParam =
                doc.createElementNS(WSConstants.WSSE_NS,
                        WSConstants.WSSE_PREFIX + ":TransformationParameters");

        WSSecurityUtil.setNamespace(transformParam,
                WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);

        Element canonElem =
                doc.createElementNS(WSConstants.SIG_NS,
                        WSConstants.SIG_PREFIX + ":CanonicalizationMethod");

        WSSecurityUtil.setNamespace(canonElem,
                WSConstants.SIG_NS,
                WSConstants.SIG_PREFIX);

        canonElem.setAttributeNS(null,
                "Algorithm",
                Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        transformParam.appendChild(canonElem);
        return transformParam;
    }

    /*
         * Extracted from org.apache.ws.security.message.WSSignEnvelope.java
         */

    protected String setWsuId(Element bodyElement) {
        String prefix =
                WSSecurityUtil.setNamespace(bodyElement,
                        WSConstants.WSU_NS,
                        WSConstants.WSU_PREFIX);
        String id = bodyElement.getAttributeNS(WSConstants.WSU_NS, "Id");
        if ((id == null) || (id.length() == 0)) {
            id = "id-" + Integer.toString(bodyElement.hashCode());
            bodyElement.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
        }
        return id;
    }

    /**
     * @param i
     */
    public void setGenerationInfo(int i) {
        generation = i;
    }

}
