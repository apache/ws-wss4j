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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.namespace.QName;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Utility methods for SAML stuff
 */
public class SAMLUtil {

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
            return SAMLUtil.getCredentialFromSubject(token, crypto, cb);
        } else {
            return SAMLUtil.getCredentialFromSubject(assertion, crypto, cb);
        }
    }
    
    /**
     * Parse a SAML Assertion as a DOM element to obtain a SAMLKeyInfo object from
     * the Subject of the assertion
     * 
     * @param elem The SAML Assertion as a DOM element
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        Element elem, Crypto crypto, CallbackHandler cb
    ) throws WSSecurityException {
        AssertionWrapper assertion = new AssertionWrapper(elem);
        return getCredentialFromSubject(assertion, crypto, cb);
    }
    
    /**
     * Parse a SAML Assertion to obtain a SAMLKeyInfo object from
     * the Subject of the assertion
     * 
     * @param assertion The SAML Assertion
     * @param crypto The Crypto instance to use to obtain certificates
     * @param cb The CallbackHandler instance used for secret keys
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
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
        
        SAMLKeyInfo samlKeyInfo = null;
        if (assertion.getSaml1() != null) {
            samlKeyInfo = getCredentialFromSubject(assertion.getSaml1(), crypto, cb);
        } else {
            samlKeyInfo = getCredentialFromSubject(assertion.getSaml2(), crypto, cb);
        }
        
        if (samlKeyInfo != null) {
            samlKeyInfo.setAssertion(assertion);
            return samlKeyInfo;
        } else {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "invalidSAMLsecurity",
                new Object[]{"cannot get certificate or key"}
            );
        }
    }
    
    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a 
     * SAML 1.1 assertion
     * @param assertion The SAML 1.1 assertion
     * @param crypto The crypto instance used to get the credential
     * @param cb The CallbackHandler used for secret keys
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    private static SAMLKeyInfo getCredentialFromSubject(
        org.opensaml.saml1.core.Assertion assertion,
        Crypto crypto,
        CallbackHandler cb
    ) throws WSSecurityException {
        for (org.opensaml.saml1.core.Statement stmt : assertion.getStatements()) {
            org.opensaml.saml1.core.Subject samlSubject = null;
            if (stmt instanceof org.opensaml.saml1.core.AttributeStatement) {
                org.opensaml.saml1.core.AttributeStatement attrStmt = 
                    (org.opensaml.saml1.core.AttributeStatement) stmt;
                samlSubject = attrStmt.getSubject();
            } else if (stmt instanceof org.opensaml.saml1.core.AuthenticationStatement) {
                org.opensaml.saml1.core.AuthenticationStatement authStmt = 
                    (org.opensaml.saml1.core.AuthenticationStatement) stmt;
                samlSubject = authStmt.getSubject();
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity",
                    new Object[] {"cannot get certificate or key"}
                );
            }
            
            if (samlSubject == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLToken", 
                    new Object[] {"for Signature (no Subject)"}
                );
            }

            Element sub = samlSubject.getSubjectConfirmation().getDOM();
            Element keyInfoElement = 
                WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", WSConstants.SIG_NS);
            return getCredentialFromKeyInfo(keyInfoElement, crypto, cb);
        }

        return null;
    }
    
    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a 
     * SAML 2 assertion
     * @param assertion The SAML 2 assertion
     * @param crypto The crypto instance used to get the credential
     * @param cb The CallbackHandler used for secret keys
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    private static SAMLKeyInfo getCredentialFromSubject(
        org.opensaml.saml2.core.Assertion assertion,
        Crypto crypto,
        CallbackHandler cb
    ) throws WSSecurityException {
        org.opensaml.saml2.core.Subject samlSubject = assertion.getSubject();
        if (samlSubject == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "invalidSAMLToken", 
                new Object[]{"for Signature (no Subject)"}
            );
        }
        List<org.opensaml.saml2.core.SubjectConfirmation> subjectConfList = 
            samlSubject.getSubjectConfirmations();
        for (org.opensaml.saml2.core.SubjectConfirmation subjectConfirmation : subjectConfList) {
            Element sub = subjectConfirmation.getDOM();
            
            Element keyInfoElement = 
                WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", WSConstants.SIG_NS);
            return getCredentialFromKeyInfo(keyInfoElement, crypto, cb);
        }

        return null;
    }
    
    /**
     * This method returns a SAMLKeyInfo corresponding to the credential found in the
     * KeyInfo (DOM Element) argument.
     * @param keyInfoElement The KeyInfo as a DOM Element
     * @param crypto The crypto instance
     * @return The credential (as a SAMLKeyInfo object)
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromKeyInfo(
        Element keyInfoElement,
        Crypto crypto,
        CallbackHandler cb
    ) throws WSSecurityException {
        //
        // First try to find an EncryptedKey or a BinarySecret via DOM
        //
        Node node = keyInfoElement.getFirstChild();
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
                            WSSecurityEngineResult.TAG_SECRET
                        );
                    return new SAMLKeyInfo(null, secret);
                } else if (el.equals(new QName(WSConstants.WST_NS, "BinarySecret"))) {
                    Text txt = (Text)node.getFirstChild();
                    return new SAMLKeyInfo(null, Base64.decode(txt.getData()));
                }
            }
            node = node.getNextSibling();
        }
        
        //
        // Next marshal the KeyInfo DOM element into a javax KeyInfo object and get the
        // (public key) credential
        //
        X509Certificate[] certs = null;
        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);

        try {
            javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = 
                keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey publicKey = ((KeyValue)xmlStructure).getPublicKey();
                    return new SAMLKeyInfo(null, publicKey);
                } else if (xmlStructure instanceof X509Data) {
                    List<?> x509Data = ((X509Data)xmlStructure).getContent();
                    for (int j = 0; j < x509Data.size(); j++) {
                        Object x509obj = x509Data.get(j);
                        if (x509obj instanceof X509Certificate) {
                            certs = new X509Certificate[1];
                            certs[0] = (X509Certificate)x509obj;
                            return new SAMLKeyInfo(null, certs);
                        } else if (x509obj instanceof X509IssuerSerial) {
                            String alias = 
                                crypto.getAliasForX509Cert(
                                    ((X509IssuerSerial)x509obj).getIssuerName(), 
                                    ((X509IssuerSerial)x509obj).getSerialNumber()
                                );
                            certs = crypto.getCertificates(alias);
                            return new SAMLKeyInfo(null, certs);
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
        return null;
    }

}
