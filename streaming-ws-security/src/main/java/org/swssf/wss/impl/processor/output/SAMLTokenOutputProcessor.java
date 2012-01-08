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
package org.swssf.wss.impl.processor.output;

import org.opensaml.common.SAMLVersion;
import org.swssf.wss.ext.*;
import org.swssf.wss.impl.saml.OpenSAMLUtil;
import org.swssf.wss.impl.saml.SAMLAssertionWrapper;
import org.swssf.wss.impl.saml.SAMLCallback;
import org.swssf.wss.impl.saml.SAMLKeyInfo;
import org.swssf.wss.impl.saml.bean.KeyInfoBean;
import org.swssf.wss.impl.saml.bean.SubjectBean;
import org.swssf.wss.impl.securityToken.ProcessorInfoSecurityToken;
import org.swssf.wss.impl.securityToken.SAMLSecurityToken;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;
import org.w3c.dom.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLTokenOutputProcessor extends AbstractOutputProcessor {

    public SAMLTokenOutputProcessor(WSSSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, final OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        try {
            final SAMLCallback samlCallback = new SAMLCallback();
            WSSUtils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), samlCallback);
            SAMLAssertionWrapper samlAssertionWrapper = new SAMLAssertionWrapper(samlCallback);

            boolean senderVouches = false;
            List<String> methods = samlAssertionWrapper.getConfirmationMethods();
            if (methods != null && methods.size() > 0) {
                String confirmMethod = methods.get(0);
                if (OpenSAMLUtil.isMethodSenderVouches(confirmMethod)) {
                    senderVouches = true;
                }
            }

            final String securityTokenReferenceId = "STRSAMLId-" + UUID.randomUUID().toString();
            final String binarySecurityTokenId = "BST-" + UUID.randomUUID().toString();
            final String tokenId = samlAssertionWrapper.getId();

            PrivateKey privateKey = null;
            X509Certificate[] certificates = null;

            if (senderVouches) {
                // prepare to sign the SAML token
                certificates = samlCallback.getIssuerCrypto().getCertificates(samlCallback.getIssuerKeyName());
                if (certificates == null) {
                    throw new WSSecurityException(
                            "No issuer certs were found to sign the SAML Assertion using issuer name: "
                                    + samlCallback.getIssuerKeyName()
                    );
                }
                try {
                    privateKey = samlCallback.getIssuerCrypto().getPrivateKey(samlCallback.getIssuerKeyName(), samlCallback.getIssuerKeyPassword());
                } catch (Exception ex) {
                    throw new WSSecurityException(ex.getMessage(), ex);
                }
            } else {
                SubjectBean subjectBean = samlCallback.getSubject();
                if (subjectBean != null) {
                    KeyInfoBean keyInfoBean = subjectBean.getKeyInfo();
                    if (keyInfoBean != null) {
                        X509Certificate x509Certificate = keyInfoBean.getCertificate();
                        if (x509Certificate != null) {
                            String alias = getSecurityProperties().getSignatureCrypto().getAliasForX509Cert(x509Certificate);
                            if (alias == null) {
                                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "aliasIsNull");
                            }
                            WSPasswordCallback wsPasswordCallback = new WSPasswordCallback(alias, WSPasswordCallback.Usage.SIGNATURE);
                            WSSUtils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), wsPasswordCallback);
                            certificates = getSecurityProperties().getSignatureCrypto().getCertificates(alias);
                            privateKey = getSecurityProperties().getSignatureCrypto().getPrivateKey(alias, wsPasswordCallback.getPassword());
                        }
                    }
                }
            }

            final SAMLKeyInfo samlKeyInfo = new SAMLKeyInfo(certificates);
            samlKeyInfo.setPublicKey(certificates[0].getPublicKey());
            samlKeyInfo.setPrivateKey(privateKey);

            final X509Certificate[] x509Certificates;
            if (certificates != null && certificates.length > 0) {
                x509Certificates = certificates;
            } else {
                x509Certificates = null;
            }

            final PrivateKey secretKey = privateKey;

            final SecurityToken securityToken;
            SecurityTokenProvider securityTokenProvider;
            if (senderVouches) {
                securityToken = new ProcessorInfoSecurityToken() {

                    private OutputProcessor outputProcessor;

                    public void setProcessor(OutputProcessor outputProcessor) {
                        this.outputProcessor = outputProcessor;
                    }

                    public String getId() {
                        return binarySecurityTokenId;
                    }

                    public Object getProcessor() {
                        return outputProcessor;
                    }

                    public boolean isAsymmetric() {
                        return true;
                    }

                    public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws WSSecurityException {
                        return secretKey;
                    }

                    public PublicKey getPublicKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws WSSecurityException {
                        return x509Certificates[0].getPublicKey();
                    }

                    public X509Certificate[] getX509Certificates() throws WSSecurityException {
                        return x509Certificates;
                    }

                    public void verify() throws WSSecurityException {
                    }

                    public SecurityToken getKeyWrappingToken() {
                        return null;
                    }

                    public String getKeyWrappingTokenAlgorithm() {
                        return null;
                    }

                    public WSSConstants.TokenType getTokenType() {
                        //todo pkiPathToken etc?
                        return WSSConstants.X509V3Token;
                    }
                };
            } else {
                securityToken = null;
            }

            final FinalSAMLTokenOutputProcessor finalSAMLTokenOutputProcessor = new FinalSAMLTokenOutputProcessor(((WSSSecurityProperties) getSecurityProperties()), getAction(), securityToken, samlAssertionWrapper, securityTokenReferenceId, binarySecurityTokenId, senderVouches);

            if (senderVouches) {

                securityTokenProvider = new SecurityTokenProvider() {
                    public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                        return securityToken;
                    }

                    public String getId() {
                        return binarySecurityTokenId;
                    }
                };

                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(binarySecurityTokenId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, binarySecurityTokenId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, securityTokenReferenceId);
            } else {
                securityTokenProvider = new SecurityTokenProvider() {
                    public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                        return new SAMLSecurityToken(
                                samlCallback.getSamlVersion(), samlKeyInfo, (WSSecurityContext) outputProcessorChain.getSecurityContext(),
                                crypto, getSecurityProperties().getCallbackHandler(), tokenId, finalSAMLTokenOutputProcessor);
                    }

                    public String getId() {
                        return tokenId;
                    }
                };

                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(tokenId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, tokenId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, tokenId);
            }

            XMLSecurityConstants.Action action = getAction();
            if (action.equals(WSSConstants.SAML_TOKEN_SIGNED)) {
                if (senderVouches) {
                    SecurePart securePart = new SecurePart(WSSConstants.SOAPMESSAGE_NS10_STRTransform, null, SecurePart.Modifier.Element, tokenId, securityTokenReferenceId);
                    outputProcessorChain.getSecurityContext().putAsList(SecurePart.class, securePart);
                }
            }
            outputProcessorChain.addProcessor(finalSAMLTokenOutputProcessor);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    class FinalSAMLTokenOutputProcessor extends AbstractOutputProcessor {

        private SecurityToken securityToken;
        private SAMLAssertionWrapper samlAssertionWrapper;
        private String securityTokenReferenceId;
        private String binarySecurityTokenReferenceId;
        private boolean senderVouches = false;

        FinalSAMLTokenOutputProcessor(WSSSecurityProperties securityProperties, XMLSecurityConstants.Action action,
                                      SecurityToken securityToken, SAMLAssertionWrapper samlAssertionWrapper,
                                      String securityTokenReferenceId, String binarySecurityTokenReferenceId,
                                      boolean senderVouches)
                throws XMLSecurityException {
            super(securityProperties, action);
            this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
            this.getAfterProcessors().add(SAMLTokenOutputProcessor.class.getName());
            this.samlAssertionWrapper = samlAssertionWrapper;
            this.securityTokenReferenceId = securityTokenReferenceId;
            this.senderVouches = senderVouches;
            this.binarySecurityTokenReferenceId = binarySecurityTokenReferenceId;
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (((WSSDocumentContext) outputProcessorChain.getDocumentContext()).isInSecurityHeader() && startElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    if (senderVouches && ((WSSSecurityProperties) getSecurityProperties()).getSignatureKeyIdentifierType() == WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                        WSSUtils.createBinarySecurityTokenStructure(this, outputProcessorChain, binarySecurityTokenReferenceId, securityToken.getX509Certificates(), getSecurityProperties().isUseSingleCert());
                    }
                    outputSamlAssertion(samlAssertionWrapper.toDOM(null), subOutputProcessorChain);
                    if (senderVouches) {
                        outputSecurityTokenReference(subOutputProcessorChain, samlAssertionWrapper, securityTokenReferenceId, samlAssertionWrapper.getId());
                    }
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }

    private void outputSecurityTokenReference(OutputProcessorChain outputProcessorChain, SAMLAssertionWrapper samlAssertionWrapper, String referenceId, String tokenId) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        if (samlAssertionWrapper.getSAMLVersion() == SAMLVersion.VERSION_11) {
            attributes.put(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE);
        } else {
            attributes.put(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE);
        }
        attributes.put(WSSConstants.ATT_wsu_Id, referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, attributes);
        attributes = new HashMap<QName, String>();
        if (samlAssertionWrapper.getSAMLVersion() == SAMLVersion.VERSION_11) {
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML10_TYPE);
        } else {
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML20_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
        createCharactersAndOutputAsEvent(outputProcessorChain, tokenId);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
    }

    //todo serialize directly from SAML XMLObject?
    private void outputSamlAssertion(Element element, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        Map<QName, String> attributes = new HashMap<QName, String>();
        Map<QName, String> namespaces = new HashMap<QName, String>();
        NamedNodeMap namedNodeMap = element.getAttributes();
        for (int i = 0; i < namedNodeMap.getLength(); i++) {
            Attr attribute = (Attr) namedNodeMap.item(i);
            if ("xmlns".equals(attribute.getPrefix()) || "xmlns".equals(attribute.getLocalName())) {
                namespaces.put(new QName(attribute.getNamespaceURI(), attribute.getLocalName(), attribute.getPrefix()), attribute.getValue());
            } else if (attribute.getPrefix() == null) {
                attributes.put(new QName(attribute.getNamespaceURI(), attribute.getLocalName()), attribute.getValue());
            } else {
                attributes.put(new QName(attribute.getNamespaceURI(), attribute.getLocalName(), attribute.getPrefix()), attribute.getValue());
            }
        }

        QName elementName = new QName(element.getNamespaceURI(), element.getLocalName(), element.getPrefix());
        createStartElementAndOutputAsEvent(outputProcessorChain, elementName, namespaces, attributes);
        NodeList childNodes = element.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node childNode = childNodes.item(i);
            switch (childNode.getNodeType()) {
                case Node.ELEMENT_NODE:
                    outputSamlAssertion((Element) childNode, outputProcessorChain);
                    break;
                case Node.TEXT_NODE:
                    createCharactersAndOutputAsEvent(outputProcessorChain, ((Text) childNode).getData());
                    break;
            }
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, elementName);
    }
}
