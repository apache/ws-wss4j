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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.conversation.ConvHandlerConstants;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org
    .apache
    .ws
    .security
    .conversation
    .message
    .token
    .RequestSecurityTokenResponse;
import org.apache.ws.security.conversation.message.token.RequestedProofToken;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.EnvelopeIdResolver;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.TrustEngine;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

/**
 * Conversation Engine follows the basic structure of SecurityEngine<link>
 *
 * @author Dimuthu (muthulee@yahoo.com)
 */
public class ConversationEngine {
    private static Log log =
        LogFactory.getLog(ConversationEngine.class.getName());
    private static Log tlog = LogFactory.getLog("org.apache.ws.security.TIME");

    private boolean doDebug = false;

    /**
     * <code>wsc:DerivedKeyToken</code> as defined in WS Secure Conversation specification.
     */
    protected static final QName DERIVEDKEY_TOKEN =
        new QName(
            ConversationConstants.WSC_NS,
            ConversationConstants.DERIVED_KEY_TOKEN_LN);

    /**
     * <code>wsc:SecurityContextToken</code> as defined in WS Secure Conversation specification.
     */
    protected static final QName SCT_TOKEN =
        new QName(
            ConversationConstants.WSC_NS,
            ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);
    /**
     * Refer WS secure Conversation specification
     */
    protected static final QName REQUESTED_SECURITY_TOKEN_RESPONSE =
        new QName(
            TrustConstants.WST_NS,
            TrustConstants.REQUEST_SECURITY_TOKEN_RESPONSE_LN);
    /**
     * <code>ds:Signature</code> as defined by XML Signature specification.
     */
    protected static final QName SIGNATURE =
        new QName(WSConstants.SIG_NS, WSConstants.SIG_LN);
    /**
     * <code>xenc:ReferenceList</code> as defined by XML Encryption specification,
     */
    protected static final QName REFERENCE_LIST =
        new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN);

    protected static final QName SCT = SecurityContextToken.TOKEN;

    protected HashMap configurator = new HashMap();

    protected String trustPropFile = null;

    protected boolean verifyTrust = false;

    protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

    static {
        org.apache.xml.security.Init.init();
    }

    public ConversationEngine(HashMap config) {

        this.configurator = config;
        //TODO :: Move this out of here.
        Boolean bool = null;
        if ((bool =
            (Boolean) configurator.get(ConvHandlerConstants.VERIFY_TRUST))
            == null) {

        } else {
            this.verifyTrust = bool.booleanValue();
            if (verifyTrust) {
                this.trustPropFile =
                    (String) configurator.get(
                        ConvHandlerConstants.TRUST_ENGINE_PROP);
            }
        }
    }

    /**
     * This method is extracted from org.apache.ws.security.SecurityEngine
     *
     * @param doc
     * @param actor
     * @param cb
     * @return
     * @throws ConversationException
     */

    public Vector processSecConvHeader(
        Document doc,
        String actor,
        DerivedKeyCallbackHandler dkcb,
        String callback)
        throws ConversationException {

        doDebug = log.isDebugEnabled();
        if (doDebug) {
            log.debug("enter processSecurityHeader()");
        }

        if (actor == null) {
            actor = "";
        }
        NodeList list =
            doc.getElementsByTagNameNS(
                WSConstants.WSSE_NS,
                WSConstants.WSSE_LN);
        int len = list.getLength();
        if (len == 0) { // No Security headers found
            return null;
        }
        if (doDebug) {
            log.debug("Found WS-Security header(s): " + len);
        }
        Element elem = null;
        Attr attr = null;
        String headerActor = null;
        SOAPConstants sc =
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        Vector convResult = new Vector();

        for (int i = 0; i < len; i++) {
            elem = (Element) list.item(i);
            attr =
                elem.getAttributeNodeNS(
                    sc.getEnvelopeURI(),
                    sc.getRoleAttributeQName().getLocalPart());
            if (attr != null) {
                headerActor = attr.getValue();
            }
            if ((headerActor == null)
                || (headerActor.length() == 0)
                || headerActor.equalsIgnoreCase(actor)
                || headerActor.equals(sc.getNextRoleURI())) {
                if (doDebug) {
                    log.debug(
                        "Processing WS-Security header for '"
                            + actor
                            + "' actor.");
                }

                try {
                    convResult = processConvHeader(elem, doc, dkcb, callback);
                } catch (WSSecurityException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (ConversationException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

            }
        }
        return convResult;
    }

    /**
     * @param doc
     * @param dkcbHandler
     * @throws ConversationException
     */

    protected Vector processConvHeader(
        Element securityHeader,
        Document doc,
        DerivedKeyCallbackHandler dkcbHandler,
        String callback)
        throws ConversationException, WSSecurityException {

        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }

        NodeList list = securityHeader.getChildNodes();
        int len = list.getLength();
        Node elem;
        String localName = null;
        String namespace = null;

        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }

        Vector returnResults = new Vector();

        for (int i = 0; i < len; i++) {
            elem = list.item(i);
            if (elem.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            QName el = new QName(elem.getNamespaceURI(), elem.getLocalName());

            if (el.equals(REQUESTED_SECURITY_TOKEN_RESPONSE)) {
                if (doDebug) {
                    log.debug("Found RequestedSecurityTokenResponse element");
                }

                returnResults.add(
                    this.handleRequestedSecurityTokenResponse(
                        (Element) elem,
                        dkcbHandler,
                        callback));

            } else if (el.equals(SIGNATURE)) {
                if (doDebug) {
                    log.debug("Found Signature element");
                }
                
                ConvEngineResult convResult =
                    this.VerifySignature((Element) elem, dkcbHandler);
                returnResults.add(convResult);
            } else if (el.equals(REFERENCE_LIST)) {
                if (doDebug) {
                    log.debug("Found Reference List element");

                }
                Vector tmpVec =
                    handleReferenceList((Element) elem, dkcbHandler);
                for (int j = 0; j < tmpVec.size(); j++) {
                    returnResults.add(tmpVec.get(j));
                }
            } else if (el.equals(SCT)) {
                SecurityContextToken sct =
                    new SecurityContextToken((Element) elem);
                String uuid = sct.getIdentifier();
                ConvEngineResult convResult =
                    new ConvEngineResult(ConvEngineResult.SCT);
                convResult.setUuid(uuid);
                returnResults.add(convResult);
            }

        }
        return returnResults;
    }

    public ConvEngineResult handleRequestedSecurityTokenResponse(
        Element eleSTRes,
        DerivedKeyCallbackHandler dkcbHandler,
        String callback)
        throws ConversationException {
        String uuid = null;
        RequestSecurityTokenResponse stRes = null;

        try {
            if (verifyTrust) {
                TrustEngine trstEngine = new TrustEngine(this.trustPropFile);
                // TODO :: Verify trust......
                System.out.println("...........Verifying trust.........");

            }

            //Now trust is verified.

            stRes = new RequestSecurityTokenResponse(eleSTRes, true);
            SecurityContextToken SCT =
                stRes.getRequestedSecurityToken().getSct();
            uuid = SCT.getIdentifier();
            RequestedProofToken proofToken = stRes.getRequestedProofToken();
            //TODO:: romove the hard coded decryption

            proofToken.doDecryption(callback, this.loadDecryptionCrypto());

            SecurityContextInfo scInfo = null;
            scInfo = new SecurityContextInfo(SCT, proofToken, 1);

            dkcbHandler.addSecurtiyContext(uuid, scInfo);
                dkcbHandler.setDerivedKeyLength(
                    uuid,
                    ((Long) configurator.get(ConvHandlerConstants.KEY_LEGNTH))
                        .longValue());
          
            log.debug(" Done SecurityToekenResponse Handled");
            ConvEngineResult res =
                new ConvEngineResult(ConvEngineResult.SECURITY_TOKEN_RESPONSE);
            res.setUuid(uuid);
            return res;

        } catch (WSTrustException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new ConversationException("");
        } catch (WSSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new ConversationException("");
        }
    }

    private ConvEngineResult VerifySignature(
        Element elem,
        DerivedKeyCallbackHandler dkcbHandler)
        throws ConversationException {
        ConvEngineResult convResult = null;
        XMLSignature sig = null;
//      System.out.println("******** at VerifySignature");
//		ByteArrayOutputStream os = new ByteArrayOutputStream();
//		XMLUtils.outputDOM(elem, os, true);
//		String osStr = os.toString();
//		System.out.println(osStr);
        try {
            sig = new XMLSignature(elem, null);
        } catch (XMLSignatureException e2) {
            throw new ConversationException("noXMLSig");
        } catch (XMLSecurityException e2) {
            throw new ConversationException("noXMLSig");
        } catch (IOException e2) {
            throw new ConversationException("noXMLSig");
        }

        String sigMethodURI = sig.getSignedInfo().getSignatureMethodURI();
        //verifying the sinature
        if (sigMethodURI.equals(XMLSignature.ALGO_ID_MAC_HMAC_SHA1)) {

            try {
                //sign.verifiyXMLHMac_SHA1_Signarue(sig, dkcbHandler);
                convResult =
                    this.verifiyXMLHMac_SHA1_Signarue(sig, dkcbHandler);
            } catch (WSSecurityException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        } else {
            throw new ConversationException("Failed");
        }
        return convResult;
    }

    /**
     * This method is extracted from WSSecurityEngine.
     * <p/>
     * Dereferences and decodes encrypted data elements.
     */
    private Vector handleReferenceList(
        Element elem,
        DerivedKeyCallbackHandler dkcbHandler)
        throws WSSecurityException {
        Vector results = new Vector();
        Document doc = elem.getOwnerDocument();
        Node tmpE = null;
        for (tmpE = elem.getFirstChild();
            tmpE != null;
            tmpE = tmpE.getNextSibling()) {
            if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
                continue;
            }
            if (tmpE.getLocalName().equals("DataReference")) {
                String dataRefURI = ((Element) tmpE).getAttribute("URI");
                ConvEngineResult convRes =
                    decryptDataRef(doc, dataRefURI, dkcbHandler);
                results.add((Object) convRes);
            } else if (tmpE.getLocalName().equals("KeyReference")) {
                String keyRefURI = ((Element) tmpE).getAttribute("URI");
            }
        }
        return results;
    }

    private ConvEngineResult decryptDataRef(
        Document doc,
        String dataRefURI,
        DerivedKeyCallbackHandler dkcbHandler)
        throws WSSecurityException {

        log.debug("ConversationEngine :: Found data refernce: " + dataRefURI);

        ConvEngineResult convResult = null;
        /*
         * Look up the encrypted data. First try wsu:Id="someURI". If no such Id then
         * try the generic lookup to find Id="someURI"
         */
        Element encBodyData = null;
        if ((encBodyData =
            WSSecurityUtil.getElementByWsuId(
                WSSConfig.getDefaultWSConfig(),
                doc,
                dataRefURI))
            == null) {
            encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
        }
        if (encBodyData == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY,
                "dataRef",
                new Object[] { dataRefURI });
        }

        Element tmpE = null;
        log.debug(
            "ConversationEngine :: Going to figure out the key to decrypt");
        byte[] decryptedBytes = null;

        /*
         * Decryption is performed in 3 major steps
         */

        //Step 1 : Get the key from SecurityTokenReference.

        log.debug(
            "ConversationEngine:: Going to look for SecurityTokenReference");

        if ((tmpE =
            (Element) WSSecurityUtil.findElement(
                (Node) encBodyData,
                "SecurityTokenReference",
                WSSConfig.getDefaultWSConfig().getWsseNS()))
            != null) {
            SecurityTokenReference secRef =
                new SecurityTokenReference(
                    WSSConfig.getDefaultWSConfig(),
                    tmpE);

            try {
                convResult =
                    this.handleSecurityTokenReference(secRef, dkcbHandler);
                decryptedBytes = convResult.getKeyAssociated();
            } catch (ConversationException e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            }

        } else {
            //TODO:: Provide more info
            throw new WSSecurityException(WSSecurityException.FAILURE);
        }

        // Step 2 :: Now figure out the encryption algorithm
        String symEncAlgo = getEncAlgo(encBodyData);
        SecretKey symmetricKey =
            WSSecurityUtil.prepareSecretKey(symEncAlgo, decryptedBytes);
        

        // Step 3 :: initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e1) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM,
                null,
                null,
                e1);
        }
        
        
     
		WSSecurityEngine eng = new WSSecurityEngine();
        boolean content = this.isContent(encBodyData);
        
        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
        }else{
        	System.out.println("Not content:-)");
        }
        
        try {
            xmlCipher.doFinal(doc, encBodyData, content);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_ENC_DEC,
                null,
                null,
                e);
        }
        return convResult;
    }

    public ConvEngineResult handleSecurityTokenReference(
        SecurityTokenReference secRef2DkToken,
        DerivedKeyCallbackHandler dkcbHandler)
        throws ConversationException {

        if (secRef2DkToken.containsReference()) {
            Reference ref = null;
            try {
                ref = secRef2DkToken.getReference();
            } catch (WSSecurityException e1) {
                e1.printStackTrace();
                throw new ConversationException(e1.getMessage());
            }

            String valueType = ref.getValueType();
            //  System.out.println("ref.getURI()" + ref.getURI());

            if (valueType.equals("http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk")) {
                Element ele =
                    WSSecurityUtil.getElementByWsuId(
                        WSSConfig.getDefaultWSConfig(),
                        secRef2DkToken.getElement().getOwnerDocument(),
                        ref.getURI());
                if (ele == null) {
                    throw new ConversationException("Cannot find  referenced Derived Key");
                }
                String uuid = null;
                DerivedKeyToken dkToken = null;
                try {
                    dkToken = new DerivedKeyToken(ele);
                    if (dkToken.getSecuityTokenReference() == null) {
                        //if dkToken doesn't have a STR                    
                        SecurityContextToken secContextTk =
                            ConversationUtil.getSCT(dkToken);
                        uuid = secContextTk.getIdentifier();
                        log.debug(
                            "ConversationEngine :: The uuid is found " + uuid);
                        DerivedKeyInfo dkInfo = new DerivedKeyInfo(dkToken);
                        dkcbHandler.addDerivedKey(uuid, dkInfo);
                    } else { ///i.e. dkToken has a STR
                        SecurityTokenReference str2Base =
                            dkToken.getSecuityTokenReference();
                        if (str2Base.containsReference()) {
                            Reference ref2Base = str2Base.getReference();
                          
                            if (ref2Base
                                .getValueType()
                                .equals("http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID")) {
                                /* ok now I have a SAML token. What should I do ?
                                 * -Decrypt the secret.
                                 * -create tempUUID
                                 * -add the scTInfo into dkcbHandler
                                 * -add the derived key token to dkcbHandler.
                                 */
                               uuid = ref2Base.getURI();
                     		   if(dkcbHandler.getSession(uuid)==null){	 
						   	       byte[] key = handleSAML(ref2Base.getElement().getOwnerDocument(), uuid);
								   System.out.println("I am here :-)");
								   SecurityContextInfo sctInfo = new SecurityContextInfo(
																	   uuid,
																	   key,
																	   1);
								   dkcbHandler.addSecurtiyContext(
																	   uuid,
																	   sctInfo);
							   }		
									DerivedKeyInfo dkInfo = new DerivedKeyInfo(dkToken);
									dkcbHandler.addDerivedKey(uuid, dkInfo);
                            } 
                            
                            
                            
                            //TODO :: Add other tokens else if      
                        } else if(str2Base.containsKeyIdentifier()){
                        	Element elem = str2Base.getFirstElement();
                        	//.getKeyIdentifier()System.out.println("KeyIdentifier :: He ehee ........");
							String value = elem.getAttribute("ValueType");
							if("http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".equals(value)){
								uuid = ((Text)elem.getChildNodes().item(0)).getNodeValue();
								if(dkcbHandler.getSession(uuid)==null){	 
									   byte[] key = handleSAML(elem.getOwnerDocument(), uuid);
									   System.out.println("UUID of SAML is"+uuid);
									   SecurityContextInfo sctInfo = new SecurityContextInfo(
																									   uuid,
																									   key,
																									   1);
									   dkcbHandler.addSecurtiyContext(uuid,sctInfo);
								}		
								DerivedKeyInfo dkInfo = new DerivedKeyInfo(dkToken);
								dkcbHandler.addDerivedKey(uuid, dkInfo);
							}
                        	
                        }else{
                            throw new ConversationException("Don't know how to process here");
                        }
                    } //////end :if dkToken has a STR
                    //TODO :: Ask ruchith to throw correct exception    
                } catch (WSSecurityException e2) {
                    // TODO Auto-generated catch block
                    e2.printStackTrace();
                } catch (ConversationException e2) {
                    // TODO Auto-generated catch block
                    e2.printStackTrace();
                }

                String identifier =
                    ConversationUtil.generateIdentifier(uuid, dkToken.getID());
                WSPasswordCallback pwCb =
                    new WSPasswordCallback(
                        identifier,
                        WSPasswordCallback.UNKNOWN);
                Callback[] callbacks = new Callback[1];
                callbacks[0] = pwCb;
                try {
                    dkcbHandler.handle(callbacks);
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                byte[] arr = pwCb.getKey();
                ConvEngineResult res =
                    new ConvEngineResult(ConvEngineResult.ENCRYPT_DERIVED_KEY);
                res.setKeyAssociated(arr);
                return res;
            } else {
                throw new ConversationException("ConversationEngine :: SecurityTokenRerence doesn't contain DerivedKeys");
            }
        } else {
            throw new ConversationException("ConversationEngine ::SecurityTokenRerence doesn't contain refernce");
        }

    }

    /**
     * @param sig - XML Signature obeject containing the XMLSignature element.
     * @param cb  - Callback handler to get the symmetric key.
     * @return
     */
    private ConvEngineResult verifiyXMLHMac_SHA1_Signarue(
        XMLSignature sig,
        DerivedKeyCallbackHandler dkcbHandler)
        throws WSSecurityException {
        
        log.debug("Verifying HMAC-SHA1 Signature......");
	    	
        String userName = null;
        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        ConvEngineResult convResult = null;
        if (sig == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN,
                "XMLSignature object is null");
        } /* Following lines of code - upto WSDocInfoStore.lookup(docHash) is copied
                                  * from the verifyXMLSignature() method.
                                  *
                                  */
       
        sig.addResourceResolver(
            EnvelopeIdResolver.getInstance(WSSConfig.getDefaultWSConfig()));
        KeyInfo info = sig.getKeyInfo();
        if (info == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY,
                "unsupportedKeyInfo");
        }
        Node node =
            WSSecurityUtil.getDirectChild(
                info.getElement(),
                SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
                wssConfig.getWsseNS());
        if (node == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY,
                "unsupportedKeyInfo");
        }
        SecurityTokenReference secRef =
            new SecurityTokenReference(
                WSSConfig.getDefaultWSConfig(),
                (Element) node);
        Document docSig = sig.getDocument();
        int docHash = docSig.hashCode();
        if (doDebug) {
            log.debug("XML Verify doc: " + docHash);
        } /*
                                  * Her we get some information about the document that is being processed,
                                  * in partucular the crypto implementation, and already detected BST that
                                  * may be used later during dereferencing.
                                  */
        WSDocInfo wsDocInfo = WSDocInfoStore.lookup(docHash);
        if (secRef.containsReference()) {
            Element token =
                secRef.getTokenElement(sig.getDocument(), wsDocInfo);
            /* check token type: We support Derivedkey tokens now.
             * We will support security context tokens.
             */
            QName el = new QName(token.getNamespaceURI(), token.getLocalName());
            if (el.equals(DERIVEDKEY_TOKEN)) {
                DerivedKeyToken dkToken = new DerivedKeyToken(token);
                DerivedKeyInfo dkInfo = null;
                
				String uuid = null;
                
                try {
					if (dkToken.getSecuityTokenReference() == null) {
						//if dkToken doesn't have a STR                    
						SecurityContextToken secContextTk =
							ConversationUtil.getSCT(dkToken);
						uuid = secContextTk.getIdentifier();
						log.debug(
							"ConversationEngine :: The uuid is found " + uuid);
						dkInfo = new DerivedKeyInfo(dkToken);
						dkcbHandler.addDerivedKey(uuid, dkInfo);
					} else { ///i.e. dkToken has a STR
						SecurityTokenReference str2Base =
							dkToken.getSecuityTokenReference();
						if (str2Base.containsReference()) {
							Reference ref2Base = str2Base.getReference();
                          //TODO:: Find where can I find the constants.
							if (ref2Base
								.getValueType()
								.equals("http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID")) {
								/* ok now I have a SAML token. What should I do ?
								 * -Decrypt the secret.
								 * -create tempUUID
								 * -add the scTInfo into dkcbHandler
								 * -add the derived key token to dkcbHandler.
								 */
								uuid = ref2Base.getURI();
								if(dkcbHandler.getSession(uuid)==null){	 
									byte[] key = handleSAML(docSig, uuid);
									System.out.println("I am here :-)");
									SecurityContextInfo sctInfo =
									new SecurityContextInfo(
										uuid,
										key,
										1);
									dkcbHandler.addSecurtiyContext(
										uuid,
									sctInfo);
								}		
									dkInfo = new DerivedKeyInfo(dkToken);
									dkcbHandler.addDerivedKey(uuid, dkInfo);
								}					
						} else if(str2Base.containsKeyIdentifier()){
													Element elem = str2Base.getFirstElement();
													//.getKeyIdentifier()System.out.println("KeyIdentifier :: He ehee ........");
													String value = elem.getAttribute("ValueType");
								if("http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".equals(value)){
									uuid = ((Text)elem.getChildNodes().item(0)).getNodeValue();
									if(dkcbHandler.getSession(uuid)==null){	 
									   byte[] key = handleSAML(elem.getOwnerDocument(), uuid);
									   System.out.println("UUID of SAML is"+uuid);
									   SecurityContextInfo sctInfo = new SecurityContextInfo(uuid,key,1);
									   dkcbHandler.addSecurtiyContext(uuid,sctInfo);
							    }		
								dkInfo = new DerivedKeyInfo(dkToken);
								dkcbHandler.addDerivedKey(uuid, dkInfo);
								}
	                        
						} else {
							throw new ConversationException("Don't know how to process here");
						}
						
					}		
                //String uuid = "aNewUuid";
                String dkId = dkToken.getID();
                userName = ConversationUtil.generateIdentifier(uuid, dkId);
                convResult =
                    new ConvEngineResult(ConvEngineResult.SIGN_DERIVED_KEY);
                    dkcbHandler.addDerivedKey(uuid, dkInfo);
                    log.debug(
                        "ConversationEngine: added for signature varification. uuil:"
                            + uuid
                            + " id:"
                            + dkId);
                } catch (ConversationException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                //TODO :: Ask ruchith to throw correct exception    
				} catch (WSSecurityException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				} 


            } else if (el.equals(SCT_TOKEN)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "SCT is not Yet supported",
                    new Object[] { el.toString()});
            } else {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "unsupportedToken",
                    new Object[] { el.toString()});
            }

            if (tlog.isDebugEnabled()) {
                t1 = System.currentTimeMillis();
            }

            try {
                // get the key from the callback handler
                WSPasswordCallback callbacks[] =
                    {
                         new WSPasswordCallback(
                            userName,
                            WSPasswordCallback.UNKNOWN)};
                try {
                    dkcbHandler.handle(callbacks);
                } catch (UnsupportedCallbackException e) {
                    e.printStackTrace();
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_SIGNATURE,
                        "password call back failed",
                        new Object[] { e.toString()});
                } // get the key and check whether it is null
                byte[] keyBytes = callbacks[0].getKey();
                if (keyBytes == null) {
                    throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY,
                        "password call bac in DerivedKeyTokenHandler failed");
                }

                convResult.setKeyAssociated(keyBytes);
                //System.out.println(new String(keyBytes));
                SecretKey symetricKey =
                    new SecretKeySpec(
                        keyBytes,
                        XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
                if (sig.checkSignatureValue(symetricKey)) {
                    if (tlog.isDebugEnabled()) {
                        t2 = System.currentTimeMillis();
                        tlog.debug(
                            "Verify: total= "
                                + (t2 - t0)
                                + ", Find-the token refernced by wsse:Reference= "
                                + (t1 - t0)
                                + ", password call back & verify= "
                                + (t2 - t1));
                    }

                } else {
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_CHECK);
                }
            } catch (XMLSignatureException e1) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }

        }

        return convResult;
    }

    /**
     * Extracted from WSSecurityEngine.
     *
     * @param encBodyData
     * @return
     * @throws WSSecurityException
     */
    private String getEncAlgo(Node encBodyData) throws WSSecurityException {
        Element tmpE =
            (Element) WSSecurityUtil.findElement(
                encBodyData,
                "EncryptionMethod",
                WSConstants.ENC_NS);
        String symEncAlgo = null;
        if (tmpE != null) {
            symEncAlgo = tmpE.getAttribute("Algorithm");
        }
        if (symEncAlgo == null) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM,
                "noEncAlgo");
        }
        if (doDebug) {
            log.debug("Sym Enc Algo: " + symEncAlgo);
        }
        return symEncAlgo;
    } //TODO :: Remove this. Temporary method.

   
	private Crypto loadDecryptionCrypto() {
			Crypto crypto = null;
			String encPropFile = (String)configurator.get(WSHandlerConstants.DEC_PROP_FILE);
			crypto = CryptoFactory.getInstance(encPropFile);
			return crypto;
		}
    
    /**
     * This method will be scrapped after the re-architecture.
     * Not so elegant work-around.
     *
     */
    private byte[] handleSAML(Document doc, String assertionId) throws ConversationException{
    	
    	try {
            Crypto crypto = this.loadDecryptionCrypto();
            //get the security header block
            //get the saml assertion
            
            Element ele=WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(), doc, doc.getDocumentElement(), false);
            Element samEle =(Element)WSSecurityUtil.getDirectChild(ele, "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion" );
//            SAMLAssertion assertion = new SAMLAssertion(samEle);
//            
//            Iterator itr = assertion.getStatements();
//            
//           	SAMLAuthenticationStatement auth = (SAMLAuthenticationStatement)itr.next();
//           	Element eleEnc = auth.getSubject().getConfirmationData();
//            

			Element eleEnc = (Element)samEle.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","EncryptedKey").item(0);
            String cb = (String)this.configurator.get(WSHandlerConstants.PW_CALLBACK_CLASS);
            
            CallbackHandler cbHandler = null;
			if (cb != null) {
				Class cbClass = null;
					try {
						cbClass = java.lang.Class.forName(cb);
				         cbHandler = (CallbackHandler) cbClass.newInstance();
                        
					} catch (ClassNotFoundException e) {
						throw new ConversationException("Cannot find passwordcallback");
					} catch (InstantiationException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
				  	} catch (IllegalAccessException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
				
			}else{
				throw new ConversationException("Cannot find passwordcallback");
			}
            
            WSSecurityEngine eng = new WSSecurityEngine();
            eng.handleEncryptedKey(eleEnc, cbHandler, crypto);	
            byte[] key = eng.getDecryptedBytes();    
            
            return key;
            
    	}catch (WSSecurityException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			throw new ConversationException("Cannot find passwordcallback");
		}
    	
    	   	
    
    
    }
   /**
    * 
    * Taken from WSSecurityEngine 
    * 
    * @param encBodyData
    * @return
    */
    private boolean isContent(Node encBodyData) {
        /*
         * Depending on the encrypted data type (Content or Element) the encBodyData either
         * holds the element whose contents where encrypted, e.g. soapenv:Body, or the
         * xenc:EncryptedData element (in case of Element encryption). In either case we need
         * to get the xenc:EncryptedData element. So get it. The findElement method returns
         * immediatly if its already the correct element.
         * Then we can get the Type attribute.
         */

        Element tmpE = (Element) WSSecurityUtil.findElement(encBodyData,
                "EncryptedData", WSConstants.ENC_NS);
        String typeStr = null;
        boolean content = true;
        if (tmpE != null) {
            typeStr = tmpE.getAttribute("Type");
        }
        if (typeStr != null) {
            content = typeStr.equals(WSConstants.ENC_NS + "Content") ? true : false;
        }
        return content;
    }
    
}
