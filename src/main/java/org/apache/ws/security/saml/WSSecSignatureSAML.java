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
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.DOMURIDereferencer;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.OpenSAMLUtil;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.WSSecurityUtil;

import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;

public class WSSecSignatureSAML extends WSSecSignature {

    private static Log log = LogFactory.getLog(WSSecSignatureSAML.class.getName());
    private boolean senderVouches = false;
    private SecurityTokenReference secRefSaml = null;
    private String secRefID = null;
    private Element samlToken = null;
    private Crypto userCrypto = null;
    private Crypto issuerCrypto = null;
    private String issuerKeyName = null;
    private String issuerKeyPW = null;
    
    private KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");

    /**
     * Constructor.
     */
    public WSSecSignatureSAML() {
        doDebug = log.isDebugEnabled();
    }

    /**
     * Builds a signed soap envelope with SAML token.
     * 
     * The method first gets an appropriate security header. According to the
     * defined parameters for certificate handling the signature elements are
     * constructed and inserted into the <code>wsse:Signature</code>
     * 
     * @param doc
     *            The unsigned SOAP envelope as <code>Document</code>
     * @param uCrypto
     *            The user's Crypto instance
     * @param assertion
     *            the complete SAML assertion
     * @param iCrypto
     *            An instance of the Crypto API to handle keystore SAML token
     *            issuer and to generate certificates
     * @param iKeyName
     *            Private key to use in case of "sender-Vouches"
     * @param iKeyPW
     *            Password for issuer private key
     * @param secHeader
     *            The Security header
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws org.apache.ws.security.WSSecurityException
     */
    public Document build(
        Document doc, Crypto uCrypto, AssertionWrapper assertion, 
        Crypto iCrypto, String iKeyName, String iKeyPW, WSSecHeader secHeader
    ) throws WSSecurityException {

        prepare(doc, uCrypto, assertion, iCrypto, iKeyName, iKeyPW, secHeader);

        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        if (parts == null) {
            parts = new ArrayList<WSEncryptionPart>(1);
            WSEncryptionPart encP = 
                new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
            parts.add(encP);
        } else {
            for (WSEncryptionPart part : parts) {
                if ("STRTransform".equals(part.getName()) && part.getId() == null) {
                    part.setId(strUri);
                }
            }
        }
        
        //
        // Add the STRTransform for the SecurityTokenReference to the SAML assertion
        // if it exists
        //
        if (secRefID != null) {
            WSEncryptionPart encP =
                new WSEncryptionPart("STRTransform", soapNamespace, "Content");
            encP.setId(secRefID);
            parts.add(encP);
        }
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            addReferencesToSign(parts, secHeader);

        prependSAMLElementsToHeader(secHeader);

        if (senderVouches) {
            computeSignature(referenceList, secHeader, secRefSaml.getElement());
        } else {
            computeSignature(referenceList, secHeader, samlToken);
        }
        
        //
        // if we have a BST prepend it in front of the Signature according to
        // strict layout rules.
        //
        if (bstToken != null) {
            prependBSTElementToHeader(secHeader);
        }

        return doc;
    }

    /**
     * Initialize a WSSec SAML Signature.
     * 
     * The method sets up and initializes a WSSec SAML Signature structure after
     * the relevant information was set. After setup of the references to
     * elements to sign may be added. After all references are added they can be
     * signed.
     * 
     * This method does not add the Signature element to the security header.
     * See <code>prependSignatureElementToHeader()</code> method.
     * 
     * @param doc
     *            The SOAP envelope as <code>Document</code>
     * @param uCrypto
     *            The user's Crypto instance
     * @param assertion
     *            the complete SAML assertion
     * @param iCrypto
     *            An instance of the Crypto API to handle keystore SAML token
     *            issuer and to generate certificates
     * @param iKeyName
     *            Private key to use in case of "sender-Vouches"
     * @param iKeyPW
     *            Password for issuer private key
     * @param secHeader
     *            The Security header
     * @throws WSSecurityException
     */
    public void prepare(
        Document doc, Crypto uCrypto, AssertionWrapper assertion, Crypto iCrypto, 
        String iKeyName, String iKeyPW, WSSecHeader secHeader
    ) throws WSSecurityException {

        if (doDebug) {
            log.debug("Beginning ST signing...");
        }

        userCrypto = uCrypto;
        issuerCrypto = iCrypto;
        document = doc;
        issuerKeyName = iKeyName;
        issuerKeyPW = iKeyPW;
        
        keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        signatureFactory = XMLSignatureFactory.getInstance("DOM");

        //
        // Get some information about the SAML token content. This controls how
        // to deal with the whole stuff. First get the Authentication statement
        // (includes Subject), then get the _first_ confirmation method only
        // thats if "senderVouches" is true.
        //
        String confirmMethod = null;
        List<String> methods = assertion.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodSenderVouches(confirmMethod)) {
            senderVouches = true;
        }
        //
        // Gather some info about the document to process and store it for
        // retrieval
        //
        wsDocInfo = new WSDocInfo(doc);

        X509Certificate[] certs = null;
        PublicKey publicKey = null;

        if (senderVouches) {
            certs = issuerCrypto.getCertificates(issuerKeyName);
            wsDocInfo.setCrypto(issuerCrypto);
        }
        //
        // in case of key holder: - get the user's certificate that _must_ be
        // included in the SAML token. To ensure the cert integrity the SAML
        // token must be signed (by the issuer). Just check if its signed, but
        // don't verify this SAML token's signature here (maybe later).
        //
        else {
            if (userCrypto == null || !assertion.isSigned()) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[] { "for SAML Signature (Key Holder)" }
                );
            }
            certs = userCrypto.getCertificates(user);
            wsDocInfo.setCrypto(userCrypto);
        }
        if ((certs == null || certs.length == 0 || certs[0] == null) 
                && publicKey == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noCertsFound",
                new Object[] { "SAML signature" }
            );
        }
        
        if (sigAlgo == null) {
            PublicKey key = null;
            if (certs != null && certs[0] != null) {
                key = certs[0].getPublicKey();
            } else if (publicKey != null) {
                key = publicKey;
            }
            
            String pubKeyAlgo = key.getAlgorithm();
            log.debug("automatic sig algo detection: " + pubKeyAlgo);
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                sigAlgo = WSConstants.DSA;
            } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                sigAlgo = WSConstants.RSA;
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "unknownSignatureAlgorithm",
                    new Object[] {
                        pubKeyAlgo
                    }
                );
            }
        }
        sig = null;
        
        try {
            C14NMethodParameterSpec c14nSpec = null;
            if (wssConfig.isWsiBSPCompliant() && canonAlgo.equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
                List<String> prefixes = 
                    getInclusivePrefixes(secHeader.getSecurityHeader(), false);
                c14nSpec = new ExcC14NParameterSpec(prefixes);
            }
            
           c14nMethod = signatureFactory.newCanonicalizationMethod(canonAlgo, c14nSpec);
        } catch (Exception ex) {
            log.error("", ex);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
            );
        }

        keyInfoUri = wssConfig.getIdAllocator().createSecureId("KeyId-", keyInfo);
        secRef = new SecurityTokenReference(doc);
        strUri = wssConfig.getIdAllocator().createSecureId("STRId-", secRef);
        secRef.setID(strUri);
        
        if (certs != null && certs.length != 0) {
            certUri = wssConfig.getIdAllocator().createSecureId("CertId-", certs[0]);
        }

        //
        // If the sender vouches, then we must sign the SAML token _and_ at
        // least one part of the message (usually the SOAP body). To do so we
        // need to - put in a reference to the SAML token. Thus we create a STR
        // and insert it into the wsse:Security header - set a reference of the
        // created STR to the signature and use STR Transform during the
        // signature
        //
        try {
            if (senderVouches) {
                secRefSaml = new SecurityTokenReference(doc);
                secRefID = wssConfig.getIdAllocator().createSecureId("STRSAMLId-", secRefSaml);
                secRefSaml.setID(secRefID);

                if (WSConstants.X509_KEY_IDENTIFIER == keyIdentifierType) {
                    Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
                    String valueType = null;
                    if (assertion.getSaml1() != null) {
                        valueType = WSConstants.WSS_SAML_KI_VALUE_TYPE;
                    } else if (assertion.getSaml2() != null) {
                        valueType = WSConstants.WSS_SAML2_KI_VALUE_TYPE;
                    }
                    keyId.setAttributeNS(
                        null, "ValueType", valueType
                    );
                    keyId.appendChild(doc.createTextNode(assertion.getId()));
                    Element elem = secRefSaml.getElement();
                    elem.appendChild(keyId);
                } else {
                    Reference ref = new Reference(doc);
                    ref.setURI("#" + assertion.getId());
                    if (assertion.getSaml1() != null) {
                        ref.setValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
                    } else if (assertion.getSaml2() != null) {
                        ref.setValueType(WSConstants.WSS_SAML2_KI_VALUE_TYPE);
                    }
                    secRefSaml.setReference(ref);
                }
                wsDocInfo.addTokenElement(secRefSaml.getElement());
            }
        } catch (Exception ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
            );
        }

        if (senderVouches) {
            switch (keyIdentifierType) {
            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(doc);
                ref.setURI("#" + certUri);
                bstToken = new X509Security(doc);
                ((X509Security) bstToken).setX509Certificate(certs[0]);
                bstToken.setID(certUri);
                wsDocInfo.addTokenElement(bstToken.getElement());
                ref.setValueType(bstToken.getValueType());
                secRef.setReference(ref);
                break;
                
            case WSConstants.X509_KEY_IDENTIFIER :
                secRef.setKeyIdentifier(certs[0]);
                break;

            default:
                throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyId");
            }
        } else {
            switch (keyIdentifierType) {
            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(doc);
                ref.setURI("#" + assertion.getId());
                if (assertion.getSaml1() != null) {
                    ref.setValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
                } else if (assertion.getSaml2() != null) {
                    ref.setValueType(WSConstants.WSS_SAML2_KI_VALUE_TYPE);
                }
                secRef.setReference(ref);
                break;
                
            case WSConstants.X509_KEY_IDENTIFIER :
                Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
                String valueType = null;
                if (assertion.getSaml1() != null) {
                    valueType = WSConstants.WSS_SAML_KI_VALUE_TYPE;
                } else if (assertion.getSaml2() != null) {
                    valueType = WSConstants.WSS_SAML2_KI_VALUE_TYPE;
                }
                keyId.setAttributeNS(
                    null, "ValueType", valueType
                );
                keyId.appendChild(doc.createTextNode(assertion.getId()));
                Element elem = secRef.getElement();
                elem.appendChild(keyId);
                break;

            default:
                throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyId");
            }
        }
        XMLStructure structure = new DOMStructure(secRef.getElement());
        wsDocInfo.addTokenElement(secRef.getElement());

        keyInfo = 
            keyInfoFactory.newKeyInfo(
                java.util.Collections.singletonList(structure), keyInfoUri
            );

        try {
            samlToken = (Element) assertion.toDOM(doc);
        } catch (MarshallingException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noSAMLdoc", null, ex
            );
        }  catch (SignatureException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noSAMLdoc", null, ex
            );
        }
        wsDocInfo.addTokenElement(samlToken);
    }

    /**
     * Prepend the SAML elements to the elements already in the Security header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the SAML elements at any position in the Security
     * header.
     * 
     * This methods first prepends the SAML security reference if mode is
     * <code>senderVouches</code>, then the SAML token itself,
     * 
     * @param secHeader
     *            The security header that holds the BST element.
     */
    public void prependSAMLElementsToHeader(WSSecHeader secHeader) {
        if (senderVouches) {
            WSSecurityUtil.prependChildElement(
                secHeader.getSecurityHeader(), secRefSaml.getElement()
            );
        }

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), samlToken);
    }

    
    /**
     * Compute the Signature over the references.
     * 
     * After references are set this method computes the Signature for them.
     * This method can be called any time after the references were set. See
     * <code>addReferencesToSign()</code>.
     * 
     * @throws WSSecurityException
     */
    public void computeSignature(
        List<javax.xml.crypto.dsig.Reference> referenceList, 
        WSSecHeader secHeader, 
        Element siblingElement
    ) throws WSSecurityException {
        try {
            java.security.Key key;
            if (senderVouches) {
                key = issuerCrypto.getPrivateKey(issuerKeyName, issuerKeyPW);
            } else {
                key = userCrypto.getPrivateKey(user, password);
            }
            SignatureMethod signatureMethod = 
                signatureFactory.newSignatureMethod(sigAlgo, null);
            SignedInfo signedInfo = 
                signatureFactory.newSignedInfo(c14nMethod, signatureMethod, referenceList);
            
            sig = signatureFactory.newXMLSignature(
                    signedInfo, 
                    keyInfo,
                    null,
                    wssConfig.getIdAllocator().createId("SIG-", null),
                    null);
            
            org.w3c.dom.Element securityHeaderElement = secHeader.getSecurityHeader();
            //
            // Prepend the signature element to the security header (after the assertion)
            //
            XMLSignContext signContext = null;
            if (siblingElement != null && siblingElement.getNextSibling() != null) {
                signContext = 
                    new DOMSignContext(key, securityHeaderElement, siblingElement.getNextSibling());
            } else {
                signContext = new DOMSignContext(key, securityHeaderElement);
            }
            signContext.putNamespacePrefix(WSConstants.SIG_NS, WSConstants.SIG_PREFIX);
            if (WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(canonAlgo)) {
                signContext.putNamespacePrefix(
                    WSConstants.C14N_EXCL_OMIT_COMMENTS, 
                    WSConstants.C14N_EXCL_OMIT_COMMENTS_PREFIX
                );
            }
            signContext.setProperty(STRTransform.TRANSFORM_WS_DOC_INFO, wsDocInfo);
            URIDereferencer dereferencer = new DOMURIDereferencer();
            ((DOMURIDereferencer)dereferencer).setWsDocInfo(wsDocInfo);
            signContext.setURIDereferencer(dereferencer);
            sig.sign(signContext);
            
            signatureValue = sig.getSignatureValue().getValue();
        } catch (Exception ex) {
            log.error(ex);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, null, null, ex
            );
        }
    }

    
}
