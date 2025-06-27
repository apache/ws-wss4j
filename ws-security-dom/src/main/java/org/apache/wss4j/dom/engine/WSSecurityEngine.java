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

package org.apache.wss4j.dom.engine;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.dom.engine.WSSConfig;
import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.dom.callback.CallbackLookup;
import org.apache.wss4j.common.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.dom.WSConstants;
import org.apache.wss4j.common.dom.WSDocInfo;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.dom.processor.Processor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * WS-Security Engine.
 */
public class WSSecurityEngine {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecurityEngine.class);

    /**
     * The WSSConfig instance used by this SecurityEngine to
     * find Processors for processing security headers
     */
    private WSSConfig wssConfig;
    private boolean doDebug;
    private CallbackLookup callbackLookup;

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
     * @return a WSHandlerResult Object containing the results of processing the security header
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(Element securityHeader, CallbackHandler cb,
     * Crypto sigVerCrypto, Crypto decCrypto)
     */
    public WSHandlerResult processSecurityHeader(
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
     * @param sigVerCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Signature verification
     * @param decCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Decryption
     * @return a WSHandlerResult Object containing the results of processing the security header
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(
     * Element securityHeader, CallbackHandler cb, Crypto sigVerCrypto, Crypto decCrypto)
     */
    public WSHandlerResult processSecurityHeader(
        Document doc,
        String actor,
        CallbackHandler cb,
        Crypto sigVerCrypto,
        Crypto decCrypto
    ) throws WSSecurityException {
        LOG.debug("enter processSecurityHeader()");

        if (actor == null) {
            actor = "";
        }
        WSHandlerResult wsResult = null;
        Element elem = WSSecurityUtil.getSecurityHeader(doc, actor);
        if (elem != null) {
            LOG.debug("Processing WS-Security header for '{}' actor.", actor);
            wsResult = processSecurityHeader(elem, actor, cb, sigVerCrypto, decCrypto);
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
     * @param sigVerCrypto   the object that implements the access to the keystore and the
     *                       handling of certificates used for Signature verification
     * @param decCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Decryption
     * @return a WSHandlerResult Object containing the results of processing the security header
     * @throws WSSecurityException
     */
    public WSHandlerResult processSecurityHeader(
        Element securityHeader,
        String actor,
        CallbackHandler cb,
        Crypto sigVerCrypto,
        Crypto decCrypto
    ) throws WSSecurityException {
        RequestData data = new RequestData();
        data.setActor(actor);
        data.setWssConfig(getWssConfig());
        data.setDecCrypto(decCrypto);
        data.setSigVerCrypto(sigVerCrypto);
        data.setCallbackHandler(cb);
        return processSecurityHeader(securityHeader, data);
    }

    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP envelope.
     * First check if a <code>wsse:Security</code> is available with the
     * defined actor.
     *
     * @param doc       the SOAP envelope as {@link Document}
     * @param requestData    the RequestData associated with the request.  It should
     *                       be able to provide the callback handler, cryptos, etc...
     *                       as needed by the processing
     * @return a WSHandlerResult Object containing the results of processing the security header
     * @throws WSSecurityException
     */
    public WSHandlerResult processSecurityHeader(
        Document doc, RequestData requestData
    ) throws WSSecurityException {
        if (requestData.getActor() == null) {
            requestData.setActor("");
        }
        String actor = requestData.getActor();
        WSHandlerResult wsResult = null;
        Element elem = WSSecurityUtil.getSecurityHeader(doc, actor);
        if (elem != null) {
            if (doDebug) {
                LOG.debug("Processing WS-Security header for '" + actor + "' actor.");
            }
            wsResult = processSecurityHeader(elem, requestData);
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
     * @param requestData    the RequestData associated with the request.  It should
     *                       be able to provide the callback handler, cryptos, etc...
     *                       as needed by the processing
     * @return a WSHandlerResult Object containing the results of processing the security header
     * @throws WSSecurityException
     */
    public WSHandlerResult processSecurityHeader(
        Element securityHeader,
        RequestData requestData
    ) throws WSSecurityException {
        if (securityHeader == null) {
            List<WSSecurityEngineResult> results = Collections.emptyList();
            Map<Integer, List<WSSecurityEngineResult>> actionResults = Collections.emptyMap();
            return new WSHandlerResult(null, results, actionResults);
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
        CallbackLookup callbackLookupToUse = callbackLookup;
        if (callbackLookupToUse == null) {
            callbackLookupToUse = new DOMCallbackLookup(securityHeader.getOwnerDocument());
        }
        wsDocInfo.setCallbackLookup(callbackLookupToUse);
        wsDocInfo.setCrypto(requestData.getSigVerCrypto());
        wsDocInfo.setSecurityHeader(securityHeader);
        requestData.setWsDocInfo(wsDocInfo);

        final WSSConfig cfg = getWssConfig();
        Node node = securityHeader.getFirstChild();

        List<WSSecurityEngineResult> returnResults = new LinkedList<>();
        boolean foundTimestamp = false;
        while (node != null) {
            Node nextSibling = node.getNextSibling();
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                QName el = new QName(node.getNamespaceURI(), node.getLocalName());

                // Check for multiple timestamps
                if (foundTimestamp && el.equals(WSConstants.TIMESTAMP)) {
                    requestData.getBSPEnforcer().handleBSPRule(BSPRule.R3227);
                } else if (el.equals(WSConstants.TIMESTAMP)) {
                    foundTimestamp = true;
                }
                //
                // Call the processor for this token. After the processor returns,
                // store it for later retrieval. The token processor may store some
                // information about the processed token
                //
                Processor p = cfg.getProcessor(el);
                if (p != null) {
                    List<WSSecurityEngineResult> results = p.handleToken((Element) node, requestData);
                    if (!results.isEmpty()) {
                        returnResults.addAll(0, results);
                    }
                } else {
                    if (doDebug) {
                        LOG.debug(
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
            if (node.getNextSibling() == null && nextSibling != null
                && nextSibling.getParentNode() != null) {
                node = nextSibling;
            } else {
                node = node.getNextSibling();
            }
        }

        WSHandlerResult handlerResult =
            new WSHandlerResult(requestData.getActor(), returnResults, wsDocInfo.getActionResults());

        // TODO off-load this to CXF Validate SAML Subject Confirmation requirements
        /*if (requestData.isValidateSamlSubjectConfirmation()) {
            Element bodyElement = callbackLookupToUse.getSOAPBody();
            DOMSAMLUtil.validateSAMLResults(handlerResult.getActionResults(), requestData.getTlsCerts(), bodyElement);
        }*/

        wsDocInfo.clear();

        return handlerResult;
    }
}
