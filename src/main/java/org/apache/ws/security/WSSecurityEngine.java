/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security;

import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.CallbackLookup;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import java.util.ArrayList;
import java.util.List;

/**
 * WS-Security Engine.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@t-online.de).
 */
public class WSSecurityEngine {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSSecurityEngine.class);

    /**
     * The WSSConfig instance used by this SecurityEngine to
     * find Processors for processing security headers
     */
    private WSSConfig wssConfig = null;
    private boolean doDebug = false;
    private CallbackLookup callbackLookup = null;
    /**
     * <code>wsse:BinarySecurityToken</code> as defined by WS Security specification
     */
    public static final QName BINARY_TOKEN = 
        new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN);
    /**
     * <code>wsse:UsernameToken</code> as defined by WS Security specification
     */
    public static final QName USERNAME_TOKEN = 
        new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN);
    /**
     * <code>wsu:Timestamp</code> as defined by OASIS WS Security specification,
     */
    public static final QName TIMESTAMP = 
        new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN);
    /**
     * <code>wsse11:signatureConfirmation</code> as defined by OASIS WS Security specification,
     */
    public static final QName SIGNATURE_CONFIRMATION = 
        new QName(WSConstants.WSSE11_NS, WSConstants.SIGNATURE_CONFIRMATION_LN);
    /**
     * <code>ds:Signature</code> as defined by XML Signature specification,
     * enhanced by WS Security specification
     */
    public static final QName SIGNATURE = 
        new QName(WSConstants.SIG_NS, WSConstants.SIG_LN);
    /**
     * <code>xenc:EncryptedKey</code> as defined by XML Encryption specification,
     * enhanced by WS Security specification
     */
    public static final QName ENCRYPTED_KEY = 
        new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN);
    /**
     * <code>xenc:EncryptedData</code> as defined by XML Encryption specification,
     * enhanced by WS Security specification
     */
    public static final QName ENCRYPTED_DATA = 
        new QName(WSConstants.ENC_NS, WSConstants.ENC_DATA_LN);
    /**
     * <code>xenc:ReferenceList</code> as defined by XML Encryption specification,
     */
    public static final QName REFERENCE_LIST = 
        new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN);
    /**
     * <code>saml:Assertion</code> as defined by SAML v1.1 specification
     */
    public static final QName SAML_TOKEN = 
        new QName(WSConstants.SAML_NS, WSConstants.ASSERTION_LN);
    
    /**
     * <code>saml:Assertion</code> as defined by SAML v2.0 specification
     */
    public static final QName SAML2_TOKEN = 
        new QName(WSConstants.SAML2_NS, WSConstants.ASSERTION_LN);

    /**
     * <code>wsc:DerivedKeyToken</code> as defined by WS-SecureConversation specification
     */
    public static final QName DERIVED_KEY_TOKEN_05_02 = 
        new QName(ConversationConstants.WSC_NS_05_02, ConversationConstants.DERIVED_KEY_TOKEN_LN);

    /**
     * <code>wsc:SecurityContextToken</code> as defined by WS-SecureConversation specification
     */
    public static final QName SECURITY_CONTEXT_TOKEN_05_02 = 
        new QName(ConversationConstants.WSC_NS_05_02, ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);

    /**
     * <code>wsc:DerivedKeyToken</code> as defined by WS-SecureConversation specification in WS-SX
     */
    public static final QName DERIVED_KEY_TOKEN_05_12 = 
        new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN);

    /**
     * <code>wsc:SecurityContextToken</code> as defined by WS-SecureConversation specification in 
     * WS-SX
     */
    public static final QName SECURITY_CONTEXT_TOKEN_05_12 = 
        new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);
    
    /**
     * @return      the WSSConfig object set on this instance
     */
    public final WSSConfig
    getWssConfig() {
        if (wssConfig == null) {
            wssConfig = WSSConfig.getNewInstance();
        }
        return wssConfig;
    }
    
    /**
     * @param cfg   the WSSConfig instance for this WSSecurityEngine to use
     *
     * @return      the WSSConfig instance previously set on this 
     *              WSSecurityEngine instance
     */
    public final WSSConfig
    setWssConfig(WSSConfig cfg) {
        WSSConfig ret = wssConfig;
        wssConfig = cfg;
        return ret;
    }
    
    /**
     * Set the CallbackLookup object to use to locate elements
     * @param callbackLookup the CallbackLookup object to use to locate elements
     */
    public void setCallbackLookup(CallbackLookup callbackLookup) {
        this.callbackLookup = callbackLookup;
    }
    
    /**
     * Get the CallbackLookup object to use to locate elements
     * @return the CallbackLookup object to use to locate elements
     */
    public CallbackLookup getCallbackLookup() {
        return callbackLookup;
    }
    
    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP envelope.
     * First check if a <code>wsse:Security</code> is available with the
     * defined actor.
     *
     * @param doc    the SOAP envelope as {@link Document}
     * @param actor  the engine works on behalf of this <code>actor</code>. Refer
     *               to the SOAP specification about <code>actor</code> or <code>role
     *               </code>
     * @param cb     a callback hander to the caller to resolve passwords during
     *               encryption and UsernameToken handling
     * @param crypto the object that implements the access to the keystore and the
     *               handling of certificates.
     * @return a result list
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(Element securityHeader, CallbackHandler cb,
     * Crypto sigCrypto, Crypto decCrypto)
     */
    public List<WSSecurityEngineResult> processSecurityHeader(
        Document doc,
        String actor,
        CallbackHandler cb,
        Crypto crypto
    ) throws WSSecurityException {
        return processSecurityHeader(doc, actor, cb, crypto, crypto);
    }

    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP envelope.
     * First check if a <code>wsse:Security</code> is available with the
     * defined actor.
     *
     * @param doc       the SOAP envelope as {@link Document}
     * @param actor     the engine works on behalf of this <code>actor</code>. Refer
     *                  to the SOAP specification about <code>actor</code> or <code>role
     *                  </code>
     * @param cb        a callback hander to the caller to resolve passwords during
     *                  encryption and UsernameToken handling
     * @param sigCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Signature
     * @param decCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Decryption
     * @return a result list
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(
     * Element securityHeader, CallbackHandler cb, Crypto sigCrypto, Crypto decCrypto)
     */
    public List<WSSecurityEngineResult> processSecurityHeader(
        Document doc,
        String actor,
        CallbackHandler cb,
        Crypto sigCrypto,
        Crypto decCrypto
    ) throws WSSecurityException {
        doDebug = log.isDebugEnabled();
        if (doDebug) {
            log.debug("enter processSecurityHeader()");
        }

        if (actor == null) {
            actor = "";
        }
        List<WSSecurityEngineResult> wsResult = null;
        Element elem = WSSecurityUtil.getSecurityHeader(doc, actor);
        if (elem != null) {
            if (doDebug) {
                log.debug("Processing WS-Security header for '" + actor + "' actor.");
            }
            wsResult = processSecurityHeader(elem, cb, sigCrypto, decCrypto);
        }
        return wsResult;
    }

    /**
     * Process the security header given the <code>wsse:Security</code> DOM
     * Element. 
     * 
     * This function loops over all direct child elements of the
     * <code>wsse:Security</code> header. If it finds a known element, it
     * transfers control to the appropriate handling function. The method
     * processes the known child elements in the same order as they appear in
     * the <code>wsse:Security</code> element. This is in accordance to the WS
     * Security specification. <p/>
     * 
     * Currently the functions can handle the following child elements:
     * 
     * <ul>
     * <li>{@link #SIGNATURE <code>ds:Signature</code>}</li>
     * <li>{@link #ENCRYPTED_KEY <code>xenc:EncryptedKey</code>}</li>
     * <li>{@link #REFERENCE_LIST <code>xenc:ReferenceList</code>}</li>
     * <li>{@link #USERNAME_TOKEN <code>wsse:UsernameToken</code>}</li>
     * <li>{@link #TIMESTAMP <code>wsu:Timestamp</code>}</li>
     * </ul>
     *
     * Note that additional child elements can be processed if appropriate
     * Processors have been registered with the WSSCondig instance set
     * on this class.
     *
     * @param securityHeader the <code>wsse:Security</code> header element
     * @param cb             a callback hander to the caller to resolve passwords during
     *                       encryption and UsernameToken handling
     * @param sigCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Signature
     * @param decCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Decryption
     * @return a List of {@link WSSecurityEngineResult}. Each element in the
     *         the List represents the result of a security action. The elements
     *         are ordered according to the sequence of the security actions in the
     *         wsse:Signature header. The List may be empty if no security processing
     *         was performed.
     * @throws WSSecurityException
     */
    public List<WSSecurityEngineResult> processSecurityHeader(
        Element securityHeader,
        CallbackHandler cb,
        Crypto sigCrypto,
        Crypto decCrypto
    ) throws WSSecurityException { 
        RequestData data = new RequestData();
        data.setWssConfig(getWssConfig());
        data.setDecCrypto(decCrypto);
        data.setSigCrypto(sigCrypto);
        data.setCallbackHandler(cb);
        return processSecurityHeader(securityHeader, data);
    }
    
    
    /**
     * Process the security header given the <code>wsse:Security</code> DOM
     * Element. 
     * 
     * This function loops over all direct child elements of the
     * <code>wsse:Security</code> header. If it finds a known element, it
     * transfers control to the appropriate handling function. The method
     * processes the known child elements in the same order as they appear in
     * the <code>wsse:Security</code> element. This is in accordance to the WS
     * Security specification. <p/>
     * 
     * Currently the functions can handle the following child elements:
     * 
     * <ul>
     * <li>{@link #SIGNATURE <code>ds:Signature</code>}</li>
     * <li>{@link #ENCRYPTED_KEY <code>xenc:EncryptedKey</code>}</li>
     * <li>{@link #REFERENCE_LIST <code>xenc:ReferenceList</code>}</li>
     * <li>{@link #USERNAME_TOKEN <code>wsse:UsernameToken</code>}</li>
     * <li>{@link #TIMESTAMP <code>wsu:Timestamp</code>}</li>
     * </ul>
     *
     * Note that additional child elements can be processed if appropriate
     * Processors have been registered with the WSSCondig instance set
     * on this class.
     *
     * @param securityHeader the <code>wsse:Security</code> header element
     * @param requestData    the RequestData associated with the request.  It should
     *                       be able to provide the callback handler, cryptos, etc...
     *                       as needed by the processing
     * @return a List of {@link WSSecurityEngineResult}. Each element in the
     *         the List represents the result of a security action. The elements
     *         are ordered according to the sequence of the security actions in the
     *         wsse:Signature header. The List may be empty if no security processing
     *         was performed.
     * @throws WSSecurityException
     */
    public List<WSSecurityEngineResult> processSecurityHeader(
        Element securityHeader,
        RequestData requestData) throws WSSecurityException {
        List<WSSecurityEngineResult> returnResults = new ArrayList<WSSecurityEngineResult>();
        if (securityHeader == null) {
            return returnResults;
        }
    
        if (requestData.getWssConfig() == null) {
            requestData.setWssConfig(getWssConfig());
        }
        
        //
        // Gather some info about the document to process and store
        // it for retrieval. Store the implementation of signature crypto
        // (no need for encryption --- yet)
        //
        WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument());
        wsDocInfo.setCallbackLookup(callbackLookup);
        wsDocInfo.setCrypto(requestData.getSigCrypto());
        wsDocInfo.setSecurityHeader(securityHeader);

        final WSSConfig cfg = getWssConfig();
        Node node = securityHeader.getFirstChild();
        
        boolean foundTimestamp = false;
        while (node != null) {
            Node nextSibling = node.getNextSibling();
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                QName el = new QName(node.getNamespaceURI(), node.getLocalName());
                
                // Check for multiple timestamps
                if (requestData.getWssConfig().isWsiBSPCompliant()) {
                    if (foundTimestamp && el.equals(TIMESTAMP)) {
                        if (doDebug) {
                            log.debug(
                                "Failure on processing multiple Timestamps as per the BSP"
                            );
                        }
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY_TOKEN, "invalidTimestamp"
                        );
                    } else if (el.equals(TIMESTAMP)) {
                        foundTimestamp = true;
                    }
                }
                //
                // Call the processor for this token. After the processor returns, 
                // store it for later retrieval. The token processor may store some
                // information about the processed token
                //
                Processor p = cfg.getProcessor(el);
                if (p != null) {
                    List<WSSecurityEngineResult> results = 
                        p.handleToken((Element) node, requestData, wsDocInfo);
                    returnResults.addAll(0, results);
                } else {
                    if (doDebug) {
                        log.debug(
                            "Unknown Element: " + node.getLocalName() + " " + node.getNamespaceURI()
                        );
                    }
                }
            }
            //
            // If the next sibling is null and the stored next sibling is not null, then we have
            // encountered an EncryptedData element which was decrypted, and so the next sibling
            // of the current node is null. In that case, go on to the previously stored next
            // sibling
            //
            if (node.getNextSibling() == null && nextSibling != null) {
                node = nextSibling;
            } else {
                node = node.getNextSibling();
            }
        }
        
        return returnResults;
    }
}
