/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.output;

import org.opensaml.common.SAMLVersion;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.saml.OpenSAMLUtil;
import org.swssf.impl.saml.SAMLAssertionWrapper;
import org.swssf.impl.saml.SAMLCallback;
import org.swssf.impl.saml.SAMLKeyInfo;
import org.swssf.impl.saml.bean.KeyInfoBean;
import org.swssf.impl.saml.bean.SubjectBean;
import org.swssf.impl.securityToken.ProcessorInfoSecurityToken;
import org.swssf.impl.securityToken.SAMLSecurityToken;
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
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SAMLTokenOutputProcessor extends AbstractOutputProcessor {

    public SAMLTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        try {
            final SAMLCallback samlCallback = new SAMLCallback();
            Utils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), samlCallback);
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
                            Utils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), wsPasswordCallback);
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

                    public Object getProccesor() {
                        return outputProcessor;
                    }

                    public boolean isAsymmetric() {
                        return true;
                    }

                    public Key getSecretKey(String algorithmURI) throws WSSecurityException {
                        return secretKey;
                    }

                    public PublicKey getPublicKey() throws WSSecurityException {
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

                    public Constants.KeyIdentifierType getKeyIdentifierType() {
                        return Constants.KeyIdentifierType.BST_DIRECT_REFERENCE;
                    }
                };
            } else {
                securityToken = null;
            }

            final FinalSAMLTokenOutputProcessor finalSAMLTokenOutputProcessor = new FinalSAMLTokenOutputProcessor(getSecurityProperties(), getAction(), securityToken, samlAssertionWrapper, securityTokenReferenceId, binarySecurityTokenId, senderVouches);

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
                outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, binarySecurityTokenId);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID, securityTokenReferenceId);
            } else {
                securityTokenProvider = new SecurityTokenProvider() {
                    public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                        return new SAMLSecurityToken(samlCallback.getSamlVersion(), samlKeyInfo, crypto, getSecurityProperties().getCallbackHandler(), tokenId, finalSAMLTokenOutputProcessor);
                    }

                    public String getId() {
                        return tokenId;
                    }
                };

                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(tokenId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, tokenId);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID, tokenId);
            }


            switch (action) {
                case SAML_TOKEN_SIGNED:
                    if (senderVouches) {
                        SecurePart securePart = new SecurePart(Constants.SOAPMESSAGE_NS10_STRTransform, null, SecurePart.Modifier.Element, tokenId, securityTokenReferenceId);
                        outputProcessorChain.getSecurityContext().putAsList(SecurePart.class, securePart);
                    }
                    break;
                case SAML_TOKEN_UNSIGNED:
                    break;
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

        FinalSAMLTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action, SecurityToken securityToken, SAMLAssertionWrapper samlAssertionWrapper, String securityTokenReferenceId, String binarySecurityTokenReferenceId, boolean senderVouches)
                throws WSSecurityException {
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
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    if (senderVouches && getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
                        outputBinarySecurityToken(outputProcessorChain, binarySecurityTokenReferenceId, securityToken.getX509Certificates(), getSecurityProperties().isUseSingleCert());
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

    private void outputSecurityTokenReference(OutputProcessorChain outputProcessorChain, SAMLAssertionWrapper samlAssertionWrapper, String referenceId, String tokenId) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        if (samlAssertionWrapper.getSAMLVersion() == SAMLVersion.VERSION_11) {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_SAML11_TOKEN_PROFILE_TYPE);
        } else {
            attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_SAML20_TOKEN_PROFILE_TYPE);
        }
        attributes.put(Constants.ATT_wsu_Id, referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);
        attributes = new HashMap<QName, String>();
        if (samlAssertionWrapper.getSAMLVersion() == SAMLVersion.VERSION_11) {
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_SAML10_TYPE);
        } else {
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_SAML20_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
        createCharactersAndOutputAsEvent(outputProcessorChain, tokenId);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
    }

    private void outputBinarySecurityToken(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate) throws XMLStreamException, WSSecurityException {
        createBinarySecurityTokenStructure(outputProcessorChain, referenceId, x509Certificates, useSingleCertificate);
    }

    //todo serialize directly from SAML XMLObject?
    private void outputSamlAssertion(Element element, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

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
