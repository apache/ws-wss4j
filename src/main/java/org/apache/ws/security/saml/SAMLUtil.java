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
import org.apache.ws.security.WSDerivedKeyTokenPrincipal;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.str.STRParser;
import org.apache.ws.security.str.SignatureSTRParser;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;

import org.opensaml.saml2.core.SubjectConfirmationData;
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

import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;

/**
 * Utility methods for SAML stuff
 */
public final class SAMLUtil {
    
    private static final QName BINARY_SECRET = 
        new QName(WSConstants.WST_NS, "BinarySecret");
    private static final QName BINARY_SECRET_05_12 = 
        new QName(WSConstants.WST_NS_05_12, "BinarySecret");
    
    private SAMLUtil() {
        // Complete
    }

    /**
     * Get an AssertionWrapper object from parsing a SecurityTokenReference that uses
     * a KeyIdentifier that points to a SAML Assertion.
     * 
     * @param secRef the SecurityTokenReference to the SAML Assertion
     * @param strElement The SecurityTokenReference DOM element
     * @param request The RequestData instance used to obtain configuration
     * @param wsDocInfo The WSDocInfo object that holds previous results
     * @return an AssertionWrapper object
     * @throws WSSecurityException
     */
    public static AssertionWrapper getAssertionFromKeyIdentifier(
        SecurityTokenReference secRef,
        Element strElement,
        RequestData request,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        String keyIdentifierValue = secRef.getKeyIdentifierValue();
        String type = secRef.getKeyIdentifierValueType();
        WSSecurityEngineResult result = wsDocInfo.getResult(keyIdentifierValue);

        AssertionWrapper assertion = null;
        Element token = null;
        if (result != null) {
            assertion = 
                (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            return assertion;
        } else {
            token = 
                secRef.findProcessedTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo,
                    request.getCallbackHandler(),
                    keyIdentifierValue, type
                );
            if (token != null) {
                if (!"Assertion".equals(token.getLocalName())) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, "invalidSAMLsecurity"
                    );
                }
                return new AssertionWrapper(token);
            }
            token = 
                secRef.findUnprocessedTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo,
                    request.getCallbackHandler(), keyIdentifierValue, type
                );
            
            if (token == null || !"Assertion".equals(token.getLocalName())) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity"
                );
            }
            Processor proc = request.getWssConfig().getProcessor(WSSecurityEngine.SAML_TOKEN);
            List<WSSecurityEngineResult> samlResult =
                proc.handleToken(token, request, wsDocInfo);
            return 
                (AssertionWrapper)samlResult.get(0).get(
                    WSSecurityEngineResult.TAG_SAML_ASSERTION
                );
        }
    }
    
    /**
     * Parse a SAML Assertion to obtain a SAMLKeyInfo object from
     * the Subject of the assertion
     * 
     * @param assertion The SAML Assertion
     * @param data The RequestData instance used to obtain configuration
     * @param docInfo A WSDocInfo instance
     * @param bspCompliant Whether to process tokens in compliance with the BSP spec or not
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        AssertionWrapper assertion, 
        RequestData data,
        WSDocInfo docInfo,
        boolean bspCompliant
    ) throws WSSecurityException {
        if (assertion.getSaml1() != null) {
            return getCredentialFromSubject(assertion.getSaml1(), data, docInfo, bspCompliant);
        } else {
            return getCredentialFromSubject(assertion.getSaml2(), data, docInfo, bspCompliant);
        }
    }
    
    /**
     * Try to get the secret key from a CallbackHandler implementation
     * @param cb a CallbackHandler implementation
     * @return An array of bytes corresponding to the secret key (can be null)
     * @throws WSSecurityException
     */
    private static byte[] getSecretKeyFromCallbackHandler(
        String id,
        CallbackHandler cb
    ) throws WSSecurityException {
        if (cb != null) {
            WSPasswordCallback pwcb = 
                new WSPasswordCallback(id, WSPasswordCallback.SECRET_KEY);
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noKey",
                        new Object[] { id }, e1);
            }
            return pwcb.getKey();
        }
        return null;
    }
    
    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a 
     * SAML 1.1 assertion
     * @param assertion The SAML 1.1 assertion
     * @param data The RequestData instance used to obtain configuration
     * @param docInfo A WSDocInfo instance
     * @param bspCompliant Whether to process tokens in compliance with the BSP spec or not
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        org.opensaml.saml1.core.Assertion assertion,
        RequestData data,
        WSDocInfo docInfo,
        boolean bspCompliant
    ) throws WSSecurityException {
        // First try to get the credential from a CallbackHandler
        byte[] key = getSecretKeyFromCallbackHandler(assertion.getID(), data.getCallbackHandler());
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        }
        
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
                org.opensaml.saml1.core.AuthorizationDecisionStatement authzStmt =
                    (org.opensaml.saml1.core.AuthorizationDecisionStatement)stmt;
                samlSubject = authzStmt.getSubject();
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
            if (keyInfoElement != null) {
                return getCredentialFromKeyInfo(keyInfoElement, data, docInfo, bspCompliant);
            }
        }

        return null;
    }
    
    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a 
     * SAML 2 assertion
     * @param assertion The SAML 2 assertion
     * @param data The RequestData instance used to obtain configuration
     * @param docInfo A WSDocInfo instance
     * @param bspCompliant Whether to process tokens in compliance with the BSP spec or not
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        org.opensaml.saml2.core.Assertion assertion,
        RequestData data,
        WSDocInfo docInfo,
        boolean bspCompliant
    ) throws WSSecurityException {
        // First try to get the credential from a CallbackHandler
        byte[] key = getSecretKeyFromCallbackHandler(assertion.getID(), data.getCallbackHandler());
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        }
        
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
            SubjectConfirmationData subjConfData = 
                subjectConfirmation.getSubjectConfirmationData();
            Element sub = subjConfData.getDOM();
            Element keyInfoElement = 
                WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", WSConstants.SIG_NS);
            if (keyInfoElement != null) {
                return getCredentialFromKeyInfo(keyInfoElement, data, docInfo, bspCompliant);
            }
        }

        return null;
    }
    
    /**
     * This method returns a SAMLKeyInfo corresponding to the credential found in the
     * KeyInfo (DOM Element) argument.
     * @param keyInfoElement The KeyInfo as a DOM Element
     * @param data The RequestData instance used to obtain configuration
     * @param docInfo A WSDocInfo instance
     * @param bspCompliant Whether to process tokens in compliance with the BSP spec or not
     * @return The credential (as a SAMLKeyInfo object)
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromKeyInfo(
        Element keyInfoElement,
        RequestData data,
        WSDocInfo docInfo,
        boolean bspCompliant
    ) throws WSSecurityException {
        //
        // First try to find an EncryptedKey, BinarySecret or a SecurityTokenReference via DOM
        //
        Node node = keyInfoElement.getFirstChild();
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                QName el = new QName(node.getNamespaceURI(), node.getLocalName());
                if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
                    EncryptedKeyProcessor proc = new EncryptedKeyProcessor();
                    List<WSSecurityEngineResult> result =
                        proc.handleToken((Element)node, data, docInfo, data.getSamlAlgorithmSuite());
                    byte[] secret = 
                        (byte[])result.get(0).get(
                            WSSecurityEngineResult.TAG_SECRET
                        );
                    return new SAMLKeyInfo(secret);
                } else if (el.equals(BINARY_SECRET) || el.equals(BINARY_SECRET_05_12)) {
                    Text txt = (Text)node.getFirstChild();
                    return new SAMLKeyInfo(Base64.decode(txt.getData()));
                } else if (SecurityTokenReference.STR_QNAME.equals(el)) {
                    STRParser strParser = new SignatureSTRParser();
                    strParser.parseSecurityTokenReference(
                        (Element)node, data, docInfo, new HashMap<String, Object>()
                    );
                    SAMLKeyInfo samlKeyInfo = new SAMLKeyInfo(strParser.getCertificates());
                    samlKeyInfo.setPublicKey(strParser.getPublicKey());
                    samlKeyInfo.setSecret(strParser.getSecretKey());
                    
                    Principal principal = strParser.getPrincipal();
                    
                    // Check for compliance against the defined AlgorithmSuite
                    AlgorithmSuite algorithmSuite = data.getSamlAlgorithmSuite(); 
                    if (algorithmSuite != null && principal instanceof WSDerivedKeyTokenPrincipal) {
                        AlgorithmSuiteValidator algorithmSuiteValidator = new
                            AlgorithmSuiteValidator(algorithmSuite);

                        algorithmSuiteValidator.checkDerivedKeyAlgorithm(
                            ((WSDerivedKeyTokenPrincipal)principal).getAlgorithm()
                        );
                        algorithmSuiteValidator.checkSignatureDerivedKeyLength(
                            ((WSDerivedKeyTokenPrincipal)principal).getLength()
                        );
                    }
                    
                    return samlKeyInfo;
                }
            }
            node = node.getNextSibling();
        }
        
        return getCredentialDirectlyFromKeyInfo(keyInfoElement, data);
    }
        
    /**
     * This method returns a SAMLKeyInfo corresponding to the credential found in the
     * KeyInfo (DOM Element) argument.
     * @param keyInfoElement The KeyInfo as a DOM Element
     * @param data The RequestData instance used to obtain configuration
     * @return The credential (as a SAMLKeyInfo object)
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialDirectlyFromKeyInfo(
        Element keyInfoElement,
        RequestData data
    ) throws WSSecurityException {
        //
        // Next marshal the KeyInfo DOM element into a javax KeyInfo object and get the
        // (public key) credential
        //
        X509Certificate[] certs = null;
        KeyInfoFactory keyInfoFactory = null;
        try {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        }
        XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);

        try {
            javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = 
                keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey publicKey = ((KeyValue)xmlStructure).getPublicKey();
                    return new SAMLKeyInfo(publicKey);
                } else if (xmlStructure instanceof X509Data) {
                    List<?> x509Data = ((X509Data)xmlStructure).getContent();
                    for (int j = 0; j < x509Data.size(); j++) {
                        Object x509obj = x509Data.get(j);
                        if (x509obj instanceof X509Certificate) {
                            certs = new X509Certificate[1];
                            certs[0] = (X509Certificate)x509obj;
                            return new SAMLKeyInfo(certs);
                        } else if (x509obj instanceof X509IssuerSerial) {
                            if (data.getSigCrypto() == null) {
                                throw new WSSecurityException(
                                    WSSecurityException.FAILURE, "noSigCryptoFile"
                                );
                            }
                            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
                            cryptoType.setIssuerSerial(
                                ((X509IssuerSerial)x509obj).getIssuerName(), 
                                ((X509IssuerSerial)x509obj).getSerialNumber()
                            );
                            certs = data.getSigCrypto().getX509Certificates(cryptoType);
                            if (certs == null || certs.length < 1) {
                                throw new WSSecurityException(
                                    WSSecurityException.FAILURE, "invalidSAMLsecurity",
                                    new Object[]{"cannot get certificate or key"}
                                );
                            }
                            return new SAMLKeyInfo(certs);
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
