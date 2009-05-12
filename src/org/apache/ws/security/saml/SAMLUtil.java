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

package org.apache.ws.security.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLObject;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.opensaml.SAMLSubjectStatement;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Utility methods for SAML stuff
 */
public class SAMLUtil {
    private static Log log = LogFactory.getLog(SAMLUtil.class.getName());

    
    
    /**
     * Extract certificates or the key available in the SAMLAssertion
     * @param elem
     * @return the SAML Key Info
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getSAMLKeyInfo(Element elem, Crypto crypto,
            CallbackHandler cb) throws WSSecurityException {
        SAMLAssertion assertion;
        try {
            assertion = new SAMLAssertion(elem);
            return getSAMLKeyInfo(assertion, crypto, cb);
        } catch (SAMLException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"}, e);
        }

    }
    
    public static SAMLKeyInfo getSAMLKeyInfo(SAMLAssertion assertion, Crypto crypto,
            CallbackHandler cb) throws WSSecurityException {
        
        //First ask the cb whether it can provide the secret
        WSPasswordCallback pwcb = new WSPasswordCallback(assertion.getId(), WSPasswordCallback.CUSTOM_TOKEN);
        if (cb != null) {
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noKey",
                        new Object[] { assertion.getId() }, e1);
            }
        }
        
        byte[] key = pwcb.getKey();
        
        if (key != null) {
            return new SAMLKeyInfo(assertion, key);
        } else {
            Iterator statements = assertion.getStatements();
            while (statements.hasNext()) {
                SAMLStatement stmt = (SAMLStatement) statements.next();
                if (stmt instanceof SAMLAttributeStatement) {
                    SAMLAttributeStatement attrStmt = (SAMLAttributeStatement) stmt;
                    SAMLSubject samlSubject = attrStmt.getSubject();
                    Element kiElem = samlSubject.getKeyInfo();
                    
                    Node node = kiElem.getFirstChild();
                    while (node != null) {
                        if (Node.ELEMENT_NODE == node.getNodeType()) {
                            QName el = new QName(node.getNamespaceURI(), node.getLocalName());
                            if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
                                EncryptedKeyProcessor proc = new EncryptedKeyProcessor();
                                proc.handleEncryptedKey((Element)node, cb, crypto, null);
                                
                                return new SAMLKeyInfo(assertion, proc.getDecryptedBytes());
                            } else if (el.equals(new QName(WSConstants.WST_NS, "BinarySecret"))) {
                                Text txt = (Text)node.getFirstChild();
                                return new SAMLKeyInfo(assertion, Base64.decode(txt.getData()));
                            }
                        }
                        node = node.getNextSibling();
                    }

                } else if (stmt instanceof SAMLAuthenticationStatement) {
                    SAMLAuthenticationStatement authStmt = (SAMLAuthenticationStatement)stmt;
                    SAMLSubject samlSubj = authStmt.getSubject(); 
                    if (samlSubj == null) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
                    }

                    Element e = samlSubj.getKeyInfo();
                    X509Certificate[] certs = null;
                    try {
                        KeyInfo ki = new KeyInfo(e, null);

                        if (ki.containsX509Data()) {
                            X509Data data = ki.itemX509Data(0);
                            XMLX509Certificate certElem = null;
                            if (data != null && data.containsCertificate()) {
                                certElem = data.itemCertificate(0);
                            }
                            if (certElem != null) {
                                X509Certificate cert = certElem.getX509Certificate();
                                certs = new X509Certificate[1];
                                certs[0] = cert;
                                return new SAMLKeyInfo(assertion, certs);
                            }
                        }

                    } catch (XMLSecurityException e3) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                "invalidSAMLsecurity",
                                new Object[]{"cannot get certificate (key holder)"}, e3);
                    }
                    
                } else {
                    throw new WSSecurityException(WSSecurityException.FAILURE,
                            "invalidSAMLsecurity",
                            new Object[]{"cannot get certificate or key "});
                }
            }
            
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate or key "});
                        
        }

    }
    
    /**
     * Extracts the certificate(s) from the SAML token reference.
     * <p/>
     *
     * @param elem The element containing the SAML token.
     * @return an array of X509 certificates
     * @throws org.apache.ws.security.WSSecurityException
     */
    public static X509Certificate[] getCertificatesFromSAML(Element elem)
            throws WSSecurityException {

        /*
         * Get some information about the SAML token content. This controls how
         * to deal with the whole stuff. First get the Authentication statement
         * (includes Subject), then get the _first_ confirmation method only.
         */
        SAMLAssertion assertion;
        try {
            assertion = new SAMLAssertion(elem);
        } catch (SAMLException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"}, e);
        }
        SAMLSubjectStatement samlSubjS = null;
        Iterator it = assertion.getStatements();
        while (it.hasNext()) {
            SAMLObject so = (SAMLObject) it.next();
            if (so instanceof SAMLSubjectStatement) {
                samlSubjS = (SAMLSubjectStatement) so;
                break;
            }
        }
        SAMLSubject samlSubj = null;
        if (samlSubjS != null) {
            samlSubj = samlSubjS.getSubject();
        }
        if (samlSubj == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
        }

//        String confirmMethod = null;
//        it = samlSubj.getConfirmationMethods();
//        if (it.hasNext()) {
//            confirmMethod = (String) it.next();
//        }
//        boolean senderVouches = false;
//        if (SAMLSubject.CONF_SENDER_VOUCHES.equals(confirmMethod)) {
//            senderVouches = true;
//        }
        Element e = samlSubj.getKeyInfo();
        X509Certificate[] certs = null;
        try {
            KeyInfo ki = new KeyInfo(e, null);

            if (ki.containsX509Data()) {
                X509Data data = ki.itemX509Data(0);
                XMLX509Certificate certElem = null;
                if (data != null && data.containsCertificate()) {
                    certElem = data.itemCertificate(0);
                }
                if (certElem != null) {
                    X509Certificate cert = certElem.getX509Certificate();
                    certs = new X509Certificate[1];
                    certs[0] = cert;
                }
            }
            // TODO: get alias name for cert, check against username set by caller
        } catch (XMLSecurityException e3) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate (key holder)"}, e3);
        }
        return certs;
    }

    public static String getAssertionId(Element envelope, String elemName, String nmSpace) throws WSSecurityException {
        String id;
        // Make the AssertionID the wsu:Id and the signature reference the same
        SAMLAssertion assertion;

        Element assertionElement = (Element) WSSecurityUtil
                .findElement(envelope, elemName, nmSpace);

        try {
            assertion = new SAMLAssertion(assertionElement);
            id = assertion.getId();
        } catch (Exception e1) {
            log.error(e1);
            throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig", null, e1);
        }
        return id;
    }

}
