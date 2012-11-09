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
package org.apache.ws.security.stax.impl.processor.input;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.binding.wss10.ObjectFactory;
import org.apache.ws.security.binding.wss10.SecurityTokenReferenceType;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.AssertionWrapper;
import org.apache.ws.security.common.saml.OpenSAMLUtil;
import org.apache.ws.security.common.saml.SAMLUtil;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.impl.securityToken.SAMLSecurityToken;
import org.apache.ws.security.stax.securityEvent.SamlTokenSecurityEvent;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.KeyValueType;
import org.apache.xml.security.binding.xmldsig.X509DataType;
import org.apache.xml.security.binding.xmlenc.EncryptedKeyType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.XMLSecurityEventReader;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.SecurityTokenFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.Comment;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.ProcessingInstruction;
import java.security.Key;
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

    private static final transient Log log = LogFactory.getLog(SAMLTokenInputHandler.class);
    private static final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

    static {
        documentBuilderFactory.setNamespaceAware(true);
    }

    /**
     * The time in seconds in the future within which the NotBefore time of an incoming
     * Assertion is valid. The default is 60 seconds.
     */
    private int futureTTL = 60;

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        final Document samlTokenDocument = (Document) parseStructure(eventQueue, index, securityProperties);

        final AssertionWrapper assertionWrapper = new AssertionWrapper(samlTokenDocument.getDocumentElement());

        //important: check the signature before we do other processing...
        if (assertionWrapper.isSigned()) {
            Signature signature = assertionWrapper.getSignature();
            if (signature == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN,
                        "empty", "no signature to validate");
            }
            SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
            try {
                validator.validate(signature);
            } catch (ValidationException ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", ex, "SAML signature validation failed");
            }

            int sigKeyInfoIdx = getSignatureKeyInfoIndex(eventQueue);
            if (sigKeyInfoIdx < 0) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noKeyInSAMLToken");
            }
            SecurityToken sigSecurityToken = parseKeyInfo(inputProcessorChain, securityProperties, eventQueue, sigKeyInfoIdx);

            if (sigSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noKeyInSAMLToken");
            }
            sigSecurityToken.verify();

            BasicX509Credential credential = new BasicX509Credential();
            if (sigSecurityToken.getX509Certificates() != null) {
                credential.setEntityCertificate(sigSecurityToken.getX509Certificates()[0]);
            } else if (sigSecurityToken.getPublicKey() != null) {
                credential.setPublicKey(sigSecurityToken.getPublicKey());
            } else {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                        "cannot get certificate or key"
                );
            }
            SignatureValidator sigValidator = new SignatureValidator(credential);
            try {
                sigValidator.validate(signature);
            } catch (ValidationException ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", ex, "SAML signature validation failed");
            }
        }

        // TODO move the following into a Validator eventually

        checkConditions(assertionWrapper);
        validateAssertion(assertionWrapper);

        String confirmMethod = null;
        List<String> methods = assertionWrapper.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }

        final SecurityToken subjectSecurityToken;

        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod)) {

            //todo shouldn't we do a crypto-lookup here first?

            // First try to get the credential from a CallbackHandler
            final byte[] subjectSecretKey = SAMLUtil.getSecretKeyFromCallbackHandler(
                    assertionWrapper.getId(), ((WSSSecurityProperties) securityProperties).getCallbackHandler());

            if (subjectSecretKey != null && subjectSecretKey.length > 0) {

                subjectSecurityToken = new AbstractInboundSecurityToken(
                        inputProcessorChain.getSecurityContext(), "",
                        XMLSecurityConstants.XMLKeyIdentifierType.NO_KEY_INFO) {
                    @Override
                    public XMLSecurityConstants.TokenType getTokenType() {
                        return XMLSecurityConstants.DefaultToken;
                    }

                    @Override
                    public boolean isAsymmetric() throws XMLSecurityException {
                        return false;
                    }

                    @Override
                    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage
                            keyUsage, String correlationID) throws XMLSecurityException {

                        Key key = super.getKey(algorithmURI, keyUsage, correlationID);
                        if (key == null) {
                            String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
                            key = new SecretKeySpec(subjectSecretKey, algoFamily);
                            setSecretKey(algorithmURI, key);
                        }
                        return key;
                    }
                };
            } else {
                // The assertion must have been signed for HOK
                if (!assertionWrapper.isSigned()) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "invalidSAMLsecurity");
                }

                int subjectKeyInfoIndex = getSubjectKeyInfoIndex(eventQueue);
                if (subjectKeyInfoIndex < 0) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noKeyInSAMLToken");
                }

                subjectSecurityToken = parseKeyInfo(inputProcessorChain, securityProperties, eventQueue, subjectKeyInfoIndex);
                if (subjectSecurityToken == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noKeyInSAMLToken");
                }
            }
        } else {
            subjectSecurityToken = null;
        }

        if (log.isDebugEnabled()) {
            log.debug("SAML Assertion issuer " + assertionWrapper.getIssuerString());
        }

        final List<QName> elementPath = getElementPath(eventQueue);
        final XMLSecEvent responsibleStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private SAMLSecurityToken securityToken = null;

            @SuppressWarnings("unchecked")
            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {
                if (this.securityToken != null) {
                    return this.securityToken;
                }

                this.securityToken = new SAMLSecurityToken(assertionWrapper.getSamlVersion(), subjectSecurityToken,
                        assertionWrapper.getIssuerString(),
                        (WSSecurityContext) inputProcessorChain.getSecurityContext(),
                        ((WSSSecurityProperties) securityProperties).getSignatureVerificationCrypto(),
                        assertionWrapper.getId(), null);

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
        samlTokenSecurityEvent.setSecurityToken((SecurityToken) securityTokenProvider.getSecurityToken());
        samlTokenSecurityEvent.setCorrelationID(assertionWrapper.getId());
        inputProcessorChain.getSecurityContext().registerSecurityEvent(samlTokenSecurityEvent);
    }

    private int getSubjectKeyInfoIndex(Deque<XMLSecEvent> eventQueue) {
        int idx = -1;
        Iterator<XMLSecEvent> xmlSecEventIterator = eventQueue.descendingIterator();
        while (xmlSecEventIterator.hasNext()) {
            XMLSecEvent xmlSecEvent = xmlSecEventIterator.next();
            idx++;
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT: {
                    QName elementName = xmlSecEvent.asStartElement().getName();
                    if (WSSConstants.TAG_dsig_KeyInfo.equals(elementName)) {
                        List<QName> elementPath = xmlSecEvent.asStartElement().getElementPath();
                        if (elementPath.size() >= 4) {
                            int lastIndex = elementPath.size() - 2;
                            if ("SubjectConfirmationData".equals(elementPath.get(lastIndex).getLocalPart()) &&
                                    "SubjectConfirmation".equals(elementPath.get(lastIndex - 1).getLocalPart()) &&
                                    "Subject".equals(elementPath.get(lastIndex - 2).getLocalPart())) {
                                return idx;
                            } else if ("SubjectConfirmation".equals(elementPath.get(lastIndex).getLocalPart()) &&
                                    "Subject".equals(elementPath.get(lastIndex - 1).getLocalPart())) {
                                return idx;
                            }
                        }
                    }
                }
            }
        }
        return idx;
    }

    private int getSignatureKeyInfoIndex(Deque<XMLSecEvent> eventQueue) {
        int idx = -1;
        Iterator<XMLSecEvent> xmlSecEventIterator = eventQueue.descendingIterator();
        while (xmlSecEventIterator.hasNext()) {
            XMLSecEvent xmlSecEvent = xmlSecEventIterator.next();
            idx++;
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT: {
                    QName elementName = xmlSecEvent.asStartElement().getName();
                    if (WSSConstants.TAG_dsig_KeyInfo.equals(elementName)) {
                        List<QName> elementPath = xmlSecEvent.asStartElement().getElementPath();
                        if (elementPath.size() >= 4) {
                            int lastIndex = elementPath.size() - 2;
                            if ("Signature".equals(elementPath.get(lastIndex).getLocalPart()) &&
                                    "Assertion".equals(elementPath.get(lastIndex - 1).getLocalPart())) {
                                return idx;
                            }
                        }
                    }
                }
            }
        }
        return idx;
    }

    private SecurityToken parseKeyInfo(InputProcessorChain inputProcessorChain, XMLSecurityProperties securityProperties,
                                       Deque<XMLSecEvent> eventQueue, int index) throws XMLSecurityException {
        XMLSecEvent xmlSecEvent = null;
        int idx = 0;
        Iterator<XMLSecEvent> xmlSecEventIterator = eventQueue.descendingIterator();
        while (xmlSecEventIterator.hasNext() && idx <= index) {
            xmlSecEvent = xmlSecEventIterator.next();
            idx++;
        }
        //forward to next start element
        while (xmlSecEventIterator.hasNext()) {
            xmlSecEvent = xmlSecEventIterator.next();
            if (xmlSecEvent.isStartElement()) {
                break;
            }
            idx++;
        }
        if (xmlSecEvent == null || !xmlSecEvent.isStartElement()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noKeyInSAMLToken");
        }

        final XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
        final QName elementName = xmlSecStartElement.getName();
        if (WSSConstants.TAG_wst_BinarySecret.equals(elementName) ||
                WSSConstants.TAG_wst0512_BinarySecret.equals(elementName)) {

            final StringBuilder stringBuilder = new StringBuilder();
            loop:
            while (xmlSecEventIterator.hasNext()) {
                xmlSecEvent = xmlSecEventIterator.next();
                switch (xmlSecEvent.getEventType()) {
                    case XMLStreamConstants.END_ELEMENT:
                        if (xmlSecEvent.asEndElement().getName().equals(elementName)) {
                            break loop;
                        }
                        break;
                    case XMLStreamConstants.CHARACTERS:
                        stringBuilder.append(xmlSecEvent.asCharacters().getText());
                        break;
                }
            }

            return new AbstractInboundSecurityToken(
                    inputProcessorChain.getSecurityContext(), "",
                    XMLSecurityConstants.XMLKeyIdentifierType.NO_KEY_INFO) {
                @Override
                public XMLSecurityConstants.TokenType getTokenType() {
                    return XMLSecurityConstants.DefaultToken;
                }

                @Override
                public boolean isAsymmetric() throws XMLSecurityException {
                    return false;
                }

                @Override
                protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage, String correlationID)
                        throws XMLSecurityException {
                    Key key = super.getKey(algorithmURI, keyUsage, correlationID);
                    if (key == null) {
                        String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
                        key = new SecretKeySpec(Base64.decodeBase64(stringBuilder.toString()), algoFamily);
                        setSecretKey(algorithmURI, key);
                    }
                    return key;
                }
            };
        } else {
            Object object = null;
            try {
                Unmarshaller unmarshaller = WSSConstants.getJaxbUnmarshaller(securityProperties.isDisableSchemaValidation());
                object = unmarshaller.unmarshal(new XMLSecurityEventReader(eventQueue, idx));
            } catch (JAXBException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, e);
            }

            if (object instanceof JAXBElement) {
                object = ((JAXBElement) object).getValue();
            }

            KeyInfoType keyInfoType = null;
            if (object instanceof X509DataType) {
                JAXBElement<X509DataType> x509DataTypeJAXBElement =
                        new org.apache.xml.security.binding.xmldsig.ObjectFactory().createX509Data((X509DataType) object);
                keyInfoType = new KeyInfoType();
                SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
                securityTokenReferenceType.getAny().add(x509DataTypeJAXBElement);
                JAXBElement<SecurityTokenReferenceType> securityTokenReferenceTypeJAXBElement =
                        new ObjectFactory().createSecurityTokenReference(securityTokenReferenceType);
                keyInfoType.getContent().add(securityTokenReferenceTypeJAXBElement);
            } else if (object instanceof EncryptedKeyType) {
                EncryptedKeyType encryptedKeyType = (EncryptedKeyType) object;
                keyInfoType = encryptedKeyType.getKeyInfo();
            } else if (object instanceof SecurityTokenReferenceType) {
                JAXBElement<SecurityTokenReferenceType> securityTokenReferenceTypeJAXBElement =
                        new ObjectFactory().createSecurityTokenReference((SecurityTokenReferenceType) object);
                keyInfoType = new KeyInfoType();
                keyInfoType.getContent().add(securityTokenReferenceTypeJAXBElement);
            } else if (object instanceof KeyValueType) {
                JAXBElement<KeyValueType> keyValueTypeJAXBElement =
                        new org.apache.xml.security.binding.xmldsig.ObjectFactory().createKeyValue((KeyValueType) object);
                keyInfoType = new KeyInfoType();
                keyInfoType.getContent().add(keyValueTypeJAXBElement);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "unsupportedKeyInfo");
            }

            return SecurityTokenFactory.getInstance().getSecurityToken(
                    keyInfoType, SecurityToken.KeyInfoUsage.SIGNATURE_VERIFICATION,
                    securityProperties, inputProcessorChain.getSecurityContext());
        }
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
                //add namespace which is not declared on current element but must be on a parent element:
                String elementNs = document.lookupNamespaceURI(xmlSecStartElement.getName().getPrefix());
                if (elementNs == null) {
                    parseXMLEvent(xmlSecStartElement.getElementNamespace(), currentNode, document);
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
                final XMLSecAttribute xmlSecAttribute = (XMLSecAttribute) xmlSecEvent;
                Attr attributeNode = document.createAttributeNS(
                        xmlSecAttribute.getName().getNamespaceURI(),
                        xmlSecAttribute.getName().getLocalPart());
                attributeNode.setPrefix(xmlSecAttribute.getName().getPrefix());
                attributeNode.setValue(xmlSecAttribute.getValue());
                ((Element) currentNode).setAttributeNodeNS(attributeNode);

                //add namespace which is not declared on current element but must be on a parent element:
                String attrNs = document.lookupNamespaceURI(xmlSecAttribute.getName().getPrefix());
                if (attrNs == null) {
                    parseXMLEvent(xmlSecAttribute.getAttributeNamespace(), currentNode, document);
                }
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
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN,
                        "empty",
                        "Illegal XMLEvent received: " + xmlSecEvent.getEventType());
        }
        return currentNode;
    }

    /**
     * Check the Conditions of the Assertion.
     */
    protected void checkConditions(AssertionWrapper assertion) throws WSSecurityException {
        DateTime validFrom = null;
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
                && assertion.getSaml2().getConditions() != null) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
                && assertion.getSaml1().getConditions() != null) {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }

        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(futureTTL);
            if (validFrom.isAfter(currentTime)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", "SAML Token condition (Not Before) not met");
            }
        }

        if (validTill != null && validTill.isBeforeNow()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                    "empty", "SAML Token condition (Not On Or After) not met");
        }
    }

    /**
     * Validate the assertion against schemas/profiles
     */
    protected void validateAssertion(AssertionWrapper assertion) throws WSSecurityException {
        if (assertion.getSaml1() != null) {
            ValidatorSuite schemaValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml1-schema-validator");
            ValidatorSuite specValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml1-spec-validator");
            try {
                schemaValidators.validate(assertion.getSaml1());
                specValidators.validate(assertion.getSaml1());
            } catch (ValidationException e) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "empty", e, "Saml Validation error: "
                );
            }
        } else if (assertion.getSaml2() != null) {
            ValidatorSuite schemaValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
            ValidatorSuite specValidators =
                    org.opensaml.Configuration.getValidatorSuite("saml2-core-spec-validator");
            try {
                schemaValidators.validate(assertion.getSaml2());
                specValidators.validate(assertion.getSaml2());
            } catch (ValidationException e) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity", e, "Saml Validation error: "
                );
            }
        }
    }
}
