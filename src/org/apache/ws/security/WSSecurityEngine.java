/*
 * Copyright  2003-2005 The Apache Software Foundation.
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

package org.apache.ws.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import java.util.Vector;

/**
 * WS-Security Engine.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@t-online.de).
 */
public class WSSecurityEngine {
    public static final String VALUE_TYPE = "ValueType";
    private static Log log = LogFactory.getLog(WSSecurityEngine.class.getName());
    private static Log tlog =
            LogFactory.getLog("org.apache.ws.security.TIME");

    private static WSSecurityEngine engine = null;
    private static WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();
    private boolean doDebug = false;
    /**
     * <code>wsse:BinarySecurityToken</code> as defined by WS Security specification
     */
    public static final QName binaryToken = new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN);
    /**
     * <code>wsse:UsernameToken</code> as defined by WS Security specification
     */
    public static final QName usernameToken = new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN);
    /**
     * <code>wsu:Timestamp</code> as defined by OASIS WS Security specification,
     */
    public static final QName timeStamp = new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN);
    /**
     * <code>wsse11:signatureConfirmation</code> as defined by OASIS WS Security specification,
     */
   public static final QName signatureConfirmation = new QName(WSConstants.WSSE11_NS, WSConstants.SIGNATURE_CONFIRMATION_LN);
    /**
     * <code>ds:Signature</code> as defined by XML Signature specification,
     * enhanced by WS Security specification
     */
    public static final QName SIGNATURE = new QName(WSConstants.SIG_NS, WSConstants.SIG_LN);
    /**
     * <code>xenc:EncryptedKey</code> as defined by XML Encryption specification,
     * enhanced by WS Security specification
     */
    public static final QName ENCRYPTED_KEY = new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN);
    /**
     * <code>xenc:ReferenceList</code> as defined by XML Encryption specification,
     */
    public static final QName REFERENCE_LIST = new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN);
    /**
     * <code>saml:Assertion</code> as defined by SAML specification
     */
    public static final QName SAML_TOKEN = new QName(WSConstants.SAML_NS, WSConstants.ASSERTION_LN);

    public WSSecurityEngine() {
    }

    /**
     * Get a singleton instance of security engine.
     * <p/>
     *
     * @return ws-security engine.
     */
    public synchronized static WSSecurityEngine getInstance() {
        if (engine == null) {
            engine = new WSSecurityEngine();
        }
        return engine;
    }

    /**
     * @param wsc set the static WSSConfig to other than default
     */
    public static void setWssConfig(WSSConfig wsc) {
        wssConfig = wsc;
    }
    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP enevelope.
     * First check if a <code>wsse:Security</code> is availabe with the
     * defined actor.
     *
     * @param doc    the SOAP envelope as {@link Document}
     * @param actor  the engine works on behalf of this <code>actor</code>. Refer
     *               to the SOAP specification about <code>actor</code> or <code>role
     *               </code>
     * @param cb     a callback hander to the caller to resolve passwords during
     *               encryption and {@link UsernameToken} handling
     * @param crypto the object that implements the access to the keystore and the
     *               handling of certificates.
     * @return a result vector
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(Element securityHeader, CallbackHandler cb,Crypto sigCrypto, Crypto decCrypto)
     */
    public Vector processSecurityHeader(Document doc,
                                        String actor,
                                        CallbackHandler cb,
                                        Crypto crypto)
            throws WSSecurityException {
        return processSecurityHeader(doc, actor, cb, crypto, crypto);
    }

    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP enevelope.
     * First check if a <code>wsse:Security</code> is availabe with the
     * defined actor.
     *
     * @param doc       the SOAP envelope as {@link Document}
     * @param actor     the engine works on behalf of this <code>actor</code>. Refer
     *                  to the SOAP specification about <code>actor</code> or <code>role
     *                  </code>
     * @param cb        a callback hander to the caller to resolve passwords during
     *                  encryption and {@link UsernameToken} handling
     * @param sigCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Signature
     * @param decCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Decryption
     * @return a result vector
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(Element securityHeader, CallbackHandler cb,Crypto sigCrypto, Crypto decCrypto)
     */
    public Vector processSecurityHeader(Document doc,
                                        String actor,
                                        CallbackHandler cb,
                                        Crypto sigCrypto,
                                        Crypto decCrypto)
            throws WSSecurityException {

        doDebug = log.isDebugEnabled();
        if (doDebug) {
            log.debug("enter processSecurityHeader()");
        }

        if (actor == null) {
            actor = "";
        }
        Vector wsResult = null;
        SOAPConstants sc = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        Element elem = WSSecurityUtil.getSecurityHeader(doc, actor, sc);
        if (elem != null) {
            if (doDebug) {
                log.debug("Processing WS-Security header for '" + actor
                        + "' actor.");
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
     * <code>wsse:Security</code> header. If it finds a knwon element, it
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
     * <li>{@link #usernameToken <code>wsse:UsernameToken</code>}</li>
     * <li>{@link #timeStamp <code>wsu:Timestamp</code>}</li>
     * </ul>
     *
     * @param securityHeader the <code>wsse:Security</code> header element
     * @param cb             a callback hander to the caller to resolve passwords during
     *                       encryption and {@link UsernameToken}handling
     * @param sigCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Signature
     * @param decCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Decryption
     * @return a Vector of {@link WSSecurityEngineResult}. Each element in the
     *         the Vector represents the result of a security action. The elements
     *         are ordered according to the sequence of the security actions in the
     *         wsse:Signature header. The Vector maybe empty if no security processing
     *         was performed.
     * @throws WSSecurityException
     */
    protected Vector processSecurityHeader(Element securityHeader,
                                           CallbackHandler cb,
                                           Crypto sigCrypto,
                                           Crypto decCrypto) throws WSSecurityException {

        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        /*
         * Gather some info about the document to process and store
         * it for retrival. Store the implemenation of signature crypto
         * (no need for encryption --- yet)
         */
        WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument().hashCode());
        wsDocInfo.setCrypto(sigCrypto);

        NodeList list = securityHeader.getChildNodes();
        int len = list.getLength();
        Node elem;
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
            Processor p = wssConfig.getProcessor(el);
            if (p != null) {
                p.handleToken((Element) elem, sigCrypto, decCrypto, cb, wsDocInfo, returnResults);
            } else {
                /*
                * Add check for a BinarySecurityToken, add info to WSDocInfo. If BST is
                * found before a Signature token this would speed up (at least a little
                * bit) the processing of STR Transform.
                */
                if (doDebug) {
                    log.debug("Unknown Element: " + elem.getLocalName() + " " + elem.getNamespaceURI());
                }
            }
        }
        if (tlog.isDebugEnabled()) {
            t2 = System.currentTimeMillis();
            tlog.debug("processHeader: total " + (t2 - t0) +
                    ", prepare " + (t1 - t0) +
                    ", handle " + (t2 - t1));
        }
        return returnResults;
    }
}
