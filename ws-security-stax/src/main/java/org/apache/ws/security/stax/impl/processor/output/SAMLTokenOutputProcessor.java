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
package org.apache.ws.security.stax.impl.processor.output;

import org.apache.ws.security.common.crypto.CryptoType;
import org.apache.ws.security.common.ext.WSPasswordCallback;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.*;
import org.apache.ws.security.common.saml.bean.KeyInfoBean;
import org.apache.ws.security.common.saml.bean.SubjectBean;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.opensaml.common.SAMLVersion;
import org.w3c.dom.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLTokenOutputProcessor extends AbstractOutputProcessor {

    public SAMLTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, final OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        try {
            final SAMLCallback samlCallback = new SAMLCallback();
            SAMLUtil.doSAMLCallback(((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler(), samlCallback);
            AssertionWrapper samlAssertionWrapper = new AssertionWrapper(samlCallback);

            // todo support setting signature and c14n algorithms
            if (samlCallback.isSignAssertion()) {
                samlAssertionWrapper.signAssertion(
                        samlCallback.getIssuerKeyName(),
                        samlCallback.getIssuerKeyPassword(),
                        samlCallback.getIssuerCrypto(),
                        samlCallback.isSendKeyValue()
                );
            }

            boolean senderVouches = false;
            List<String> methods = samlAssertionWrapper.getConfirmationMethods();
            if (methods != null && methods.size() > 0) {
                String confirmMethod = methods.get(0);
                if (OpenSAMLUtil.isMethodSenderVouches(confirmMethod)) {
                    senderVouches = true;
                }
            }

            final String securityTokenReferenceId = IDGenerator.generateID(null);
            final String binarySecurityTokenId = IDGenerator.generateID(null);
            final String tokenId = samlAssertionWrapper.getId();

            PrivateKey privateKey = null;
            X509Certificate[] certificates = null;

            if (senderVouches) {
                // prepare to sign the SAML token
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(samlCallback.getIssuerKeyName());
                certificates = samlCallback.getIssuerCrypto().getX509Certificates(cryptoType);
                if (certificates == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "empty", "No issuer certs were found to sign the SAML Assertion using issuer name: "
                                    + samlCallback.getIssuerKeyName()
                    );
                }
                try {
                    privateKey = samlCallback.getIssuerCrypto().getPrivateKey(samlCallback.getIssuerKeyName(), samlCallback.getIssuerKeyPassword());
                } catch (Exception ex) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex);
                }
            } else {
                SubjectBean subjectBean = samlCallback.getSubject();
                if (subjectBean != null) {
                    KeyInfoBean keyInfoBean = subjectBean.getKeyInfo();
                    if (keyInfoBean != null) {
                        X509Certificate x509Certificate = keyInfoBean.getCertificate();
                        if (x509Certificate != null) {
                            String alias = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getX509Identifier(x509Certificate);
                            if (alias == null) {
                                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "aliasIsNull");
                            }
                            WSPasswordCallback wsPasswordCallback = new WSPasswordCallback(alias, WSPasswordCallback.Usage.SIGNATURE);
                            WSSUtils.doPasswordCallback(((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler(), wsPasswordCallback);
                            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                            cryptoType.setAlias(alias);
                            certificates = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getX509Certificates(cryptoType);
                            privateKey = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getPrivateKey(alias, wsPasswordCallback.getPassword());
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

            final GenericOutboundSecurityToken securityToken;
            SecurityTokenProvider securityTokenProvider;
            if (senderVouches) {
                securityToken = new GenericOutboundSecurityToken(binarySecurityTokenId,
                        WSSConstants.X509V3Token, secretKey, x509Certificates);
            } else {
                securityToken = null;
            }

            final FinalSAMLTokenOutputProcessor finalSAMLTokenOutputProcessor =
                    new FinalSAMLTokenOutputProcessor(securityToken, samlAssertionWrapper,
                            securityTokenReferenceId, binarySecurityTokenId, senderVouches);
            finalSAMLTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalSAMLTokenOutputProcessor.setAction(getAction());
            finalSAMLTokenOutputProcessor.init(outputProcessorChain);

            if (senderVouches) {

                securityTokenProvider = new SecurityTokenProvider() {

                    @SuppressWarnings("unchecked")
                    @Override
                    public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                        return securityToken;
                    }

                    @Override
                    public String getId() {
                        return binarySecurityTokenId;
                    }
                };

                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(binarySecurityTokenId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, binarySecurityTokenId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, securityTokenReferenceId);
            } else {
                securityTokenProvider = new SecurityTokenProvider() {

                    private GenericOutboundSecurityToken samlSecurityToken;

                    @SuppressWarnings("unchecked")
                    @Override
                    public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                        if (this.samlSecurityToken != null) {
                            return this.samlSecurityToken;
                        }
                        XMLSecurityConstants.TokenType tokenType;
                        if (samlCallback.getSamlVersion() == SAMLVersion.VERSION_10) {
                            tokenType = WSSConstants.Saml10Token;
                        } else if (samlCallback.getSamlVersion() == SAMLVersion.VERSION_11) {
                            tokenType = WSSConstants.Saml11Token;
                        } else {
                            tokenType = WSSConstants.Saml20Token;
                        }
                        this.samlSecurityToken = new GenericOutboundSecurityToken(tokenId, tokenType, samlKeyInfo.getPrivateKey(), samlKeyInfo.getCerts());
                        this.samlSecurityToken.setProcessor(finalSAMLTokenOutputProcessor);
                        return this.samlSecurityToken;
                    }

                    @Override
                    public String getId() {
                        return tokenId;
                    }
                };

                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(tokenId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, tokenId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, tokenId);
            }

            XMLSecurityConstants.Action action = getAction();
            if (action.equals(WSSConstants.SAML_TOKEN_SIGNED) && senderVouches) {
                SecurePart securePart = new SecurePart(new QName(WSSConstants.SOAPMESSAGE_NS10_STRTransform), tokenId, securityTokenReferenceId, SecurePart.Modifier.Element);
                outputProcessorChain.getSecurityContext().putAsMap(WSSConstants.SIGNATURE_PARTS, tokenId, securePart);
            }
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalSAMLTokenOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;
        private final AssertionWrapper assertionWrapper;
        private final String securityTokenReferenceId;
        private final String binarySecurityTokenReferenceId;
        private boolean senderVouches = false;

        FinalSAMLTokenOutputProcessor(OutboundSecurityToken securityToken, AssertionWrapper assertionWrapper,
                                      String securityTokenReferenceId, String binarySecurityTokenReferenceId,
                                      boolean senderVouches) throws XMLSecurityException {
            super();
            this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
            this.addAfterProcessor(SAMLTokenOutputProcessor.class.getName());
            this.assertionWrapper = assertionWrapper;
            this.securityTokenReferenceId = securityTokenReferenceId;
            this.senderVouches = senderVouches;
            this.binarySecurityTokenReferenceId = binarySecurityTokenReferenceId;
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlSecEvent);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    if (senderVouches && ((WSSSecurityProperties) getSecurityProperties()).getSignatureKeyIdentifierType() == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                        WSSUtils.createBinarySecurityTokenStructure(this, outputProcessorChain, binarySecurityTokenReferenceId, securityToken.getX509Certificates(), getSecurityProperties().isUseSingleCert());
                    }
                    outputSamlAssertion(assertionWrapper.toDOM(null), subOutputProcessorChain);
                    if (senderVouches) {
                        outputSecurityTokenReference(subOutputProcessorChain, assertionWrapper, securityTokenReferenceId, assertionWrapper.getId());
                    }
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }

    private void outputSecurityTokenReference(OutputProcessorChain outputProcessorChain, AssertionWrapper assertionWrapper, String referenceId, String tokenId) throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
        if (assertionWrapper.getSamlVersion() == SAMLVersion.VERSION_11) {
            attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE));
        } else {
            attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE));
        }
        attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, referenceId));
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);
        attributes = new ArrayList<XMLSecAttribute>(1);
        if (assertionWrapper.getSamlVersion() == SAMLVersion.VERSION_11) {
            attributes.add(createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML10_TYPE));
        } else {
            attributes.add(createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML20_TYPE));
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, false, attributes);
        createCharactersAndOutputAsEvent(outputProcessorChain, tokenId);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
    }

    //todo serialize directly from SAML XMLObject?
    private void outputSamlAssertion(Element element, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        NamedNodeMap namedNodeMap = element.getAttributes();
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(namedNodeMap.getLength());
        List<XMLSecNamespace> namespaces = new ArrayList<XMLSecNamespace>(namedNodeMap.getLength());
        for (int i = 0; i < namedNodeMap.getLength(); i++) {
            Attr attribute = (Attr) namedNodeMap.item(i);
            if (attribute.getPrefix() == null) {
                attributes.add(createAttribute(new QName(attribute.getNamespaceURI(), attribute.getLocalName()), attribute.getValue()));
            } else if ("xmlns".equals(attribute.getPrefix()) || "xmlns".equals(attribute.getLocalName())) {
                namespaces.add(createNamespace(attribute.getLocalName(), attribute.getValue()));
            } else {
                attributes.add(createAttribute(new QName(attribute.getNamespaceURI(), attribute.getLocalName(), attribute.getPrefix()), attribute.getValue()));
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
