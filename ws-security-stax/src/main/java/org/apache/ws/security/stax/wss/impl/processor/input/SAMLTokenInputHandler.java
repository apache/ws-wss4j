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
package org.apache.ws.security.stax.wss.impl.processor.input;

import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.crypto.CryptoType;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.AssertionWrapper;
import org.apache.ws.security.common.saml.OpenSAMLUtil;
import org.apache.ws.security.common.saml.SAMLKeyInfo;
import org.apache.ws.security.stax.wss.ext.*;
import org.apache.ws.security.stax.wss.impl.saml.WSSSAMLKeyInfoProcessor;
import org.apache.ws.security.stax.wss.impl.securityToken.SAMLSecurityToken;
import org.apache.ws.security.stax.wss.securityEvent.SamlTokenSecurityEvent;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Comment;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.ProcessingInstruction;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

/**
 * Processor for the SAML Assertion XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    private static final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

    static {
        documentBuilderFactory.setNamespaceAware(true);
    }

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        final Document samlTokenDocument = (Document) parseStructure(eventQueue, index, securityProperties);

        final AssertionWrapper assertionWrapper = new AssertionWrapper(samlTokenDocument.getDocumentElement());

        if (assertionWrapper.isSigned()) {
            assertionWrapper.verifySignature(
                    new WSSSAMLKeyInfoProcessor(),
                    ((WSSSecurityProperties) securityProperties).getSignatureVerificationCrypto(),
                    true // TODO
            );
            // Verify trust on the signature
            final SAMLKeyInfo samlIssuerKeyInfo = assertionWrapper.getSignatureKeyInfo();
            verifySignedAssertion(samlIssuerKeyInfo, 
                    (WSSSecurityProperties) securityProperties);
        }
        // Parse the HOK subject if it exists
        assertionWrapper.parseHOKSubject(
                new WSSSAMLKeyInfoProcessor(),
                ((WSSSecurityProperties)securityProperties).getSignatureVerificationCrypto(),
                securityProperties.getCallbackHandler(),
                true // TODO
        );
        
        // TODO move this into a Validator eventually
        String confirmMethod = null;
        List<String> methods = assertionWrapper.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod)) {
            if (assertionWrapper.getSubjectKeyInfo() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKeyInSAMLToken");
            }
            // The assertion must have been signed for HOK
            if (!assertionWrapper.isSigned()) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }
        }
        
        final SAMLKeyInfo samlSubjectKeyInfo = assertionWrapper.getSubjectKeyInfo();

        if (logger.isDebugEnabled()) {
            logger.debug("SAML Assertion issuer " + assertionWrapper.getIssuerString());
        }

        final List<QName> elementPath = getElementPath(eventQueue);
        final XMLSecEvent responsibleStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private SecurityToken securityToken = null;

            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {
                if (this.securityToken != null) {
                    return this.securityToken;
                }

                this.securityToken = new SAMLSecurityToken(assertionWrapper.getSamlVersion(), samlSubjectKeyInfo,
                        assertionWrapper.getIssuerString(),
                        (WSSecurityContext) inputProcessorChain.getSecurityContext(), 
                        ((WSSSecurityProperties)securityProperties).getSignatureVerificationCrypto(),
                        securityProperties.getCallbackHandler(), assertionWrapper.getId(), null);

                this.securityToken.setElementPath(elementPath);
                this.securityToken.setXMLSecEvent(responsibleStartXMLEvent);
                return this.securityToken;
            }

            @Override
            public String getId() {
                return assertionWrapper.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(assertionWrapper.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        SamlTokenSecurityEvent samlTokenSecurityEvent = new SamlTokenSecurityEvent();
        samlTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(samlTokenSecurityEvent);
    }

    @SuppressWarnings("unchecked")
    @Override
    protected <T> T parseStructure(Deque<XMLSecEvent> eventDeque, int index, XMLSecurityProperties securityProperties)
            throws XMLSecurityException {
        Document document;
        try {
            document = documentBuilderFactory.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
        }

        Iterator<XMLSecEvent> xmlSecEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        while (curIdx++ < index) {
            xmlSecEventIterator.next();
        }

        Node currentNode = document;
        while (xmlSecEventIterator.hasNext()) {
            XMLSecEvent next = xmlSecEventIterator.next();
            currentNode = parseXMLEvent(next, currentNode, document);
        }
        return (T) document;
    }

    //todo custom SAML unmarshaller directly to XMLObject?
    public Node parseXMLEvent(XMLSecEvent xmlSecEvent, Node currentNode, Document document) throws WSSecurityException {
        switch (xmlSecEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                Element element = document.createElementNS(xmlSecStartElement.getName().getNamespaceURI(),
                        xmlSecStartElement.getName().getLocalPart());
                if (xmlSecStartElement.getName().getPrefix() != null && !xmlSecStartElement.getName().getPrefix().isEmpty()) {
                    element.setPrefix(xmlSecStartElement.getName().getPrefix());
                }
                currentNode = currentNode.appendChild(element);
                @SuppressWarnings("unchecked")
                Iterator<XMLSecNamespace> namespaceIterator = xmlSecStartElement.getNamespaces();
                while (namespaceIterator.hasNext()) {
                    XMLSecNamespace next = namespaceIterator.next();
                    parseXMLEvent(next, currentNode, document);
                }
                @SuppressWarnings("unchecked")
                Iterator<XMLSecAttribute> attributesIterator = xmlSecStartElement.getAttributes();
                while (attributesIterator.hasNext()) {
                    XMLSecAttribute next = attributesIterator.next();
                    parseXMLEvent(next, currentNode, document);
                }
                break;
            case XMLStreamConstants.END_ELEMENT:
                if (currentNode.getParentNode() != null) {
                    currentNode = currentNode.getParentNode();
                }
                break;
            case XMLStreamConstants.PROCESSING_INSTRUCTION:
                Node piNode = document.createProcessingInstruction(
                        ((ProcessingInstruction) xmlSecEvent).getTarget(),
                        ((ProcessingInstruction) xmlSecEvent).getTarget()
                );
                currentNode.appendChild(piNode);
                break;
            case XMLStreamConstants.CHARACTERS:
                Node characterNode = document.createTextNode(xmlSecEvent.asCharacters().getData());
                currentNode.appendChild(characterNode);
                break;
            case XMLStreamConstants.COMMENT:
                Node commentNode = document.createComment(((Comment) xmlSecEvent).getText());
                currentNode.appendChild(commentNode);
                break;
            case XMLStreamConstants.START_DOCUMENT:
                break;
            case XMLStreamConstants.END_DOCUMENT:
                return currentNode;
            case XMLStreamConstants.ATTRIBUTE:
                Attr attributeNode = document.createAttributeNS(
                        ((Attribute) xmlSecEvent).getName().getNamespaceURI(),
                        ((Attribute) xmlSecEvent).getName().getLocalPart());
                attributeNode.setPrefix(((Attribute) xmlSecEvent).getName().getPrefix());
                attributeNode.setValue(((Attribute) xmlSecEvent).getValue());
                ((Element) currentNode).setAttributeNodeNS(attributeNode);
                break;
            case XMLStreamConstants.DTD:
                //todo?:
                /*
                Node dtdNode = document.getDoctype().getEntities()
                ((DTD)xmlSecEvent).getDocumentTypeDeclaration():
                ((DTD)xmlSecEvent).getEntities()
                */
                break;
            case XMLStreamConstants.NAMESPACE:
                Namespace namespace = (Namespace) xmlSecEvent;
                Attr namespaceNode;
                String prefix = namespace.getPrefix();
                if (prefix == null || prefix.isEmpty()) {
                    namespaceNode = document.createAttributeNS(WSSConstants.NS_XML, "xmlns");
                } else {
                    namespaceNode = document.createAttributeNS(WSSConstants.NS_XML, "xmlns:" + prefix);
                }
                namespaceNode.setValue(namespace.getNamespaceURI());
                ((Element) currentNode).setAttributeNodeNS(namespaceNode);
                break;
            default:
                throw new WSSecurityException("Illegal XMLEvent received: " + xmlSecEvent.getEventType());
        }
        return currentNode;
    }
    
    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     *
     * @return A Credential instance
     * @throws WSSecurityException
     */
    public void verifySignedAssertion(SAMLKeyInfo samlKeyInfo, WSSSecurityProperties securityProperties) throws XMLSecurityException {
        validate(samlKeyInfo.getCerts(), samlKeyInfo.getPublicKey(), securityProperties);
    }

    /**
     * Validate the credential argument. It must contain a non-null X509Certificate chain
     * or a PublicKey. A Crypto implementation is also required to be set.
     * <p/>
     * This implementation first attempts to verify trust on the certificate (chain). If
     * this is not successful, then it will attempt to verify trust on the Public Key.
     *
     * @throws WSSecurityException on a failed validation
     */
    protected void validate(X509Certificate[] certs, PublicKey publicKey, WSSSecurityProperties securityProperties) throws XMLSecurityException {
        Crypto crypto = securityProperties.getSignatureVerificationCrypto();
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSigCryptoFile");
        }

        if (certs != null && certs.length > 0) {
            validateCertificates(certs);
            boolean trust = false;
            if (certs.length == 1) {
                trust = verifyTrustInCert(certs[0], crypto);
            } else {
                trust = verifyTrustInCerts(certs, crypto);
            }
            if (trust) {
                return;
            }
        }
        if (publicKey != null) {
            boolean trust = validatePublicKey(publicKey, crypto);
            if (trust) {
                return;
            }
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
    }

    /**
     * Validate the certificates by checking the validity of each cert
     *
     * @throws WSSecurityException
     */
    protected void validateCertificates(X509Certificate[] certificates)
            throws WSSecurityException {
        try {
            for (int i = 0; i < certificates.length; i++) {
                certificates[i].checkValidity();
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_CHECK, "invalidCert", e
            );
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_CHECK, "invalidCert", e
            );
        }
    }
    
    /**
     * Check to see if the certificate argument is in the keystore
     *
     * @param crypto The Crypto instance to use
     * @param cert   The certificate to check
     * @return true if cert is in the keystore
     * @throws WSSecurityException
     */
    protected boolean isCertificateInKeyStore(Crypto crypto, X509Certificate cert) throws XMLSecurityException {
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
        cryptoType.setIssuerSerial(issuerString, issuerSerial);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        //
        // If a certificate has been found, the certificates must be compared
        // to ensure against phony DNs (compare encoded form including signature)
        //
        if (foundCerts != null && foundCerts[0] != null && foundCerts[0].equals(cert)) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Direct trust for certificate with " + cert.getSubjectX500Principal().getName()
                );
            }
            return true;
        }
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "No certificate found for subject from issuer with " + issuerString
                            + " (serial " + issuerSerial + ")"
            );
        }
        return false;
    }

    
    /**
     * Evaluate whether a given certificate should be trusted.
     * <p/>
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer
     * might be fooled by a phony DN (String!)
     *
     * @param cert   the certificate that should be validated against the keystore
     * @param crypto A crypto instance to use for trust validation
     * @return true if the certificate is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCert(X509Certificate cert, Crypto crypto) throws XMLSecurityException {
        String subjectString = cert.getSubjectX500Principal().getName();
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        if (logger.isDebugEnabled()) {
            logger.debug("Transmitted certificate has subject " + subjectString);
            logger.debug(
                    "Transmitted certificate has issuer " + issuerString + " (serial "
                            + issuerSerial + ")"
            );
        }

        //
        // FIRST step - Search the keystore for the transmitted certificate
        //
        if (isCertificateInKeyStore(crypto, cert)) {
            return true;
        }

        //
        // SECOND step - Search for the issuer cert (chain) of the transmitted certificate in the
        // keystore or the truststore
        //
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(issuerString);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        // If the certs have not been found, the issuer is not in the keystore/truststore
        // As a direct result, do not trust the transmitted certificate
        if (foundCerts == null || foundCerts.length < 1) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "No certs found in keystore for issuer " + issuerString
                                + " of certificate for " + subjectString
                );
            }
            return false;
        }

        //
        // THIRD step
        // Check the certificate trust path for the issuer cert chain
        //
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Preparing to validate certificate path for issuer " + issuerString
            );
        }
        //
        // Form a certificate chain from the transmitted certificate
        // and the certificate(s) of the issuer from the keystore/truststore
        //
        X509Certificate[] x509certs = new X509Certificate[foundCerts.length + 1];
        x509certs[0] = cert;
        System.arraycopy(foundCerts, 0, x509certs, 1, foundCerts.length);

        //
        // Use the validation method from the crypto to check whether the subjects'
        // certificate was really signed by the issuer stated in the certificate
        //
        if (crypto.verifyTrust(x509certs)) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Certificate path has been verified for certificate with subject "
                                + subjectString
                );
            }
            return true;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Certificate path could not be verified for certificate with subject "
                            + subjectString
            );
        }
        return false;
    }

    /**
     * Evaluate whether the given certificate chain should be trusted.
     *
     * @param certificates the certificate chain that should be validated against the keystore
     * @return true if the certificate chain is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCerts(X509Certificate[] certificates, Crypto crypto) throws XMLSecurityException {
        //
        // Use the validation method from the crypto to check whether the subjects'
        // certificate was really signed by the issuer stated in the certificate
        //
        if (certificates != null && certificates.length > 0
                && crypto.verifyTrust(certificates)) {
            return true;
        }
        return false;
    }

    /**
     * Validate a public key
     *
     * @throws WSSecurityException
     */
    protected boolean validatePublicKey(PublicKey publicKey, Crypto crypto) throws XMLSecurityException {
        return crypto.verifyTrust(publicKey);
    }


}
