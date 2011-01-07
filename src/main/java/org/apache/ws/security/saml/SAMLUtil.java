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
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;

import org.opensaml.common.SAMLObject;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectStatement;
import org.opensaml.xml.io.UnmarshallingException;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.namespace.QName;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

/**
 * Utility methods for SAML stuff
 */
public class SAMLUtil {
    private static Log log = LogFactory.getLog(SAMLUtil.class.getName());

    /**
     * Get a SAMLKeyInfo object from parsing a SecurityTokenReference that uses
     * a KeyIdentifier that points to a SAML Assertion.
     * 
     * @param secRef the SecurityTokenReference to the SAML Assertion
     * @param strElement The SecurityTokenReference DOM element
     * @param crypto The Crypto instance to use to obtain certificates
     * @param cb The CallbackHandler instance used for secret keys
     * @param wsDocInfo The WSDocInfo object that holds previous results
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getSamlKeyInfoFromKeyIdentifier(
        SecurityTokenReference secRef,
        Element strElement,
        Crypto crypto,
        CallbackHandler cb,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        String keyIdentifierValue = secRef.getKeyIdentifierValue();
        WSSecurityEngineResult result = wsDocInfo.getResult(keyIdentifierValue);

        AssertionWrapper assertion = null;
        Element token = null;
        if (result != null) {
            assertion = 
                (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        } else {
            token = 
                secRef.getKeyIdentifierTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo, cb
                );
        }

        if (crypto == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noSigCryptoFile"
            );
        }
        if (assertion == null) {
            return SAMLUtil.getSAMLKeyInfo(token, crypto, cb);
        } else {
            return SAMLUtil.getSAMLKeyInfo(assertion, crypto, cb);
        }
    }
    
    /**
     * Parse a SAML Assertion as a DOM element to obtain a SAMLKeyInfo object.
     * 
     * @param elem The SAML Assertion as a DOM element
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getSAMLKeyInfo(
        Element elem, Crypto crypto, CallbackHandler cb
    ) throws WSSecurityException {
        try {
            AssertionWrapper assertion = new AssertionWrapper(elem);
            return getSAMLKeyInfo(assertion, crypto, cb);
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"}, e);
        }
    }
    
    /**
     * Parse a SAML Assertion to obtain a SAMLKeyInfo object.
     * 
     * @param assertion The SAML Assertion
     * @param crypto The Crypto instance to use to obtain certificates
     * @param cb The CallbackHandler instance used for secret keys
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getSAMLKeyInfo(
        AssertionWrapper assertion, Crypto crypto, CallbackHandler cb
    ) throws WSSecurityException {
        // First ask the cb whether it can provide the secret
        if (cb != null) {
            WSPasswordCallback pwcb = 
                new WSPasswordCallback(assertion.getId(), WSPasswordCallback.CUSTOM_TOKEN);
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noKey",
                        new Object[] { assertion.getId() }, e1);
            }
            byte[] key = pwcb.getKey();
            if (key != null) {
                return new SAMLKeyInfo(assertion, key);
            }
        }
        
        // WARNING!  THIS IS HARD CODED TO SAML v1.1
        org.opensaml.saml1.core.Assertion saml11Assertion = assertion.getSaml1();
        Iterator<?> statements = saml11Assertion.getStatements().iterator();
        while (statements.hasNext()) {
            Statement stmt = (Statement) statements.next();
            if (stmt instanceof AttributeStatement) {
                AttributeStatement attrStmt = (AttributeStatement) stmt;
                Subject samlSubject = attrStmt.getSubject();
                Element sub = samlSubject.getSubjectConfirmation().getDOM();
                Element kiElem = 
                    WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", WSConstants.SIG_NS);

                Node node = kiElem.getFirstChild();
                while (node != null) {
                    if (Node.ELEMENT_NODE == node.getNodeType()) {
                        QName el = new QName(node.getNamespaceURI(), node.getLocalName());
                        if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
                            EncryptedKeyProcessor proc = new EncryptedKeyProcessor();
                            WSDocInfo docInfo = new WSDocInfo(node.getOwnerDocument());
                            List<WSSecurityEngineResult> result =
                                proc.handleToken((Element)node, null, crypto, cb, docInfo, null);
                            byte[] secret = 
                                (byte[])result.get(0).get(
                                    WSSecurityEngineResult.TAG_DECRYPTED_KEY
                                );
                            return new SAMLKeyInfo(assertion, secret);
                        } else if (el.equals(new QName(WSConstants.WST_NS, "BinarySecret"))) {
                            Text txt = (Text)node.getFirstChild();
                            return new SAMLKeyInfo(assertion, Base64.decode(txt.getData()));
                        }
                    }
                    node = node.getNextSibling();
                }
            } else if (stmt instanceof AuthenticationStatement) {
                AuthenticationStatement authStmt = (AuthenticationStatement) stmt;
                Subject samlSubj = authStmt.getSubject();
                if (samlSubj == null) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, "invalidSAMLToken", 
                        new Object[]{"for Signature (no Subject)"}
                    );
                }

                Element sub = samlSubj.getSubjectConfirmation().getDOM();
                Element keyInfoElement = 
                    WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", WSConstants.SIG_NS);
                X509Certificate[] certs = null;
                KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");
                XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);

                try {
                    KeyInfo keyInfo = keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
                    List<?> list = keyInfo.getContent();

                    for (int i = 0; i < list.size(); i++) {
                        XMLStructure xmlStructure = (XMLStructure) list.get(i);
                        if (xmlStructure instanceof KeyValue) {
                            PublicKey publicKey = ((KeyValue)xmlStructure).getPublicKey();
                            return new SAMLKeyInfo(assertion, publicKey);
                        } else if (xmlStructure instanceof X509Data) {
                            List<?> x509Data = ((X509Data)xmlStructure).getContent();
                            for (int j = 0; j < x509Data.size(); j++) {
                                Object x509obj = x509Data.get(j);
                                if (x509obj instanceof X509Certificate) {
                                    certs = new X509Certificate[1];
                                    certs[0] = (X509Certificate)x509obj;
                                    return new SAMLKeyInfo(assertion, certs);
                                } else if (x509obj instanceof X509IssuerSerial) {
                                    String alias = 
                                        crypto.getAliasForX509Cert(
                                            ((X509IssuerSerial)x509obj).getIssuerName(), 
                                            ((X509IssuerSerial)x509obj).getSerialNumber()
                                        );
                                    certs = crypto.getCertificates(alias);
                                    return new SAMLKeyInfo(assertion, certs);
                                }
                            }
                        }
                    }
                } catch (Exception ex) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, "invalidSAMLsecurity",
                        new Object[]{"cannot get certificate or key"}, ex
                    );
                }
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate or key"}
                );
            }
        }

        throw new WSSecurityException(
            WSSecurityException.FAILURE, "invalidSAMLsecurity",
            new Object[]{"cannot get certificate or key"}
        );
    }
    
    /**
     * Extracts the certificate(s) from the SAML token reference.
     * <p/>
     *
     * @param elem The element containing the SAML token.
     * @return an array of X509 certificates
     * @throws org.apache.ws.security.WSSecurityException
     */
    public static X509Certificate[] getCertificatesFromSAML(
        Element elem
    ) throws WSSecurityException {
        /*
         * Get some information about the SAML token content. This controls how
         * to deal with the whole stuff. First get the Authentication statement
         * (includes Subject), then get the _first_ confirmation method only.
         */
        AssertionWrapper assertion;
        try {
            assertion = new AssertionWrapper(elem);
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"}, e);
        }
        SubjectStatement samlSubjS = null;

        // WARNING!  THIS IS HARD CODED TO SAML v1.1
        org.opensaml.saml1.core.Assertion saml11Assertion = assertion.getSaml1();

        Iterator it = saml11Assertion.getStatements().iterator();
        while (it.hasNext()) {
            SAMLObject so = (SAMLObject) it.next();
            if (so instanceof SubjectStatement) {
                samlSubjS = (SubjectStatement) so;
                break;
            }
        }
        Subject samlSubj = null;
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
        
        Element sub = samlSubj.getSubjectConfirmation().getDOM();
        Element kiElem = 
            WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", WSConstants.SIG_NS);
        X509Certificate[] certs = null;
        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        XMLStructure keyInfoStructure = new DOMStructure(kiElem);
        
        try {
            KeyInfo keyInfo = keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof X509Data) {
                    List<?> x509Data = ((X509Data)xmlStructure).getContent();
                    for (int j = 0; j < x509Data.size(); j++) {
                        Object x509obj = x509Data.get(j);
                        if (x509obj instanceof X509Certificate) {
                            certs = new X509Certificate[1];
                            certs[0] = (X509Certificate)x509obj;
                            break;
                        }
                    }
                }
            }
            // TODO: get alias name for cert, check against username set by caller
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate or key "}, ex);
        }
        
        return certs;
    }
    
    public static String getAssertionId(
        Element envelope, 
        String elemName, 
        String nmSpace
    ) throws WSSecurityException {
        String id;
        // Make the AssertionID the wsu:Id and the signature reference the same
        AssertionWrapper assertion;

        Element assertionElement = 
            (Element)WSSecurityUtil.findElement(envelope, elemName, nmSpace);

        try {
            assertion = new AssertionWrapper(assertionElement);
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
