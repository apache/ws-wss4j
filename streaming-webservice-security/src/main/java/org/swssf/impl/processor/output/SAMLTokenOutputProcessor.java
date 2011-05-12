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

import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.saml.OpenSAMLUtil;
import org.swssf.impl.saml.SAMLAssertionWrapper;
import org.swssf.impl.saml.SAMLCallback;
import org.swssf.impl.saml.SAMLKeyInfo;
import org.swssf.impl.securityToken.SAMLSecurityToken;
import org.w3c.dom.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.PrivateKey;
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

    public SAMLTokenOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        super(securityProperties);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.processEvent(xmlEvent);

        try {
            SAMLCallback samlCallback = new SAMLCallback();
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

            final String referenceId = "STRSAMLId-" + UUID.randomUUID().toString();

            if (senderVouches) {

                // prepare to sign the SAML token
                X509Certificate[] issuerCerts = samlCallback.getIssuerCrypto().getCertificates(samlCallback.getIssuerKeyName());
                if (issuerCerts == null) {
                    throw new WSSecurityException(
                            "No issuer certs were found to sign the SAML Assertion using issuer name: "
                                    + samlCallback.getIssuerKeyName()
                    );
                }

                PrivateKey privateKey = null;
                try {
                    privateKey = samlCallback.getIssuerCrypto().getPrivateKey(samlCallback.getIssuerKeyName(), samlCallback.getIssuerKeyPassword());
                } catch (Exception ex) {
                    throw new WSSecurityException(ex.getMessage(), ex);
                }

                final String tokenId = samlAssertionWrapper.getId();
                final SAMLKeyInfo samlKeyInfo = new SAMLKeyInfo(issuerCerts);
                samlKeyInfo.setPublicKey(issuerCerts[0].getPublicKey());
                samlKeyInfo.setPrivateKey(privateKey);

                SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
                    public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                        return new SAMLSecurityToken(samlKeyInfo, crypto, getSecurityProperties().getCallbackHandler());
                    }

                    public String getId() {
                        return tokenId;
                    }
                };

                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(tokenId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, tokenId);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID, referenceId);
                SecurePart securePart = new SecurePart(Constants.SOAPMESSAGE_NS10_STRTransform, null, SecurePart.Modifier.Element, tokenId, referenceId);
                outputProcessorChain.getSecurityContext().putAsList(SecurePart.class, securePart);
            }
            outputProcessorChain.addProcessor(new FinalSAMLTokenOutputProcessor(getSecurityProperties(), samlAssertionWrapper, referenceId));
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
    }

    class FinalSAMLTokenOutputProcessor extends AbstractOutputProcessor {

        private SAMLAssertionWrapper samlAssertionWrapper;
        private String referenceId;

        FinalSAMLTokenOutputProcessor(SecurityProperties securityProperties, SAMLAssertionWrapper samlAssertionWrapper, String referenceId)
                throws WSSecurityException {
            super(securityProperties);
            this.getAfterProcessors().add(SAMLTokenOutputProcessor.class.getName());
            this.samlAssertionWrapper = samlAssertionWrapper;
            this.referenceId = referenceId;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    outputSamlAssertion(samlAssertionWrapper.toDOM(null), subOutputProcessorChain);
                    outputSecurityTokenReference(subOutputProcessorChain, referenceId, samlAssertionWrapper.getId());
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }

    private void outputSecurityTokenReference(OutputProcessorChain outputProcessorChain, String referenceId, String tokenId) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_wsse11_TokenType, Constants.NS_SAML11_TOKEN_PROFILE_TYPE);
        attributes.put(Constants.ATT_wsu_Id, referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);
        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_SAML10_TYPE);
        createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
        createCharactersAndOutputAsEvent(outputProcessorChain, tokenId);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
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
