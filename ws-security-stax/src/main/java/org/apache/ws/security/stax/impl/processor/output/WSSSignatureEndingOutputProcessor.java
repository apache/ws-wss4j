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

import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.algorithms.SignatureAlgorithm;
import org.apache.xml.security.stax.impl.processor.output.AbstractSignatureEndingOutputProcessor;
import org.apache.xml.security.stax.impl.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author $Author: coheigea $
 * @version $Revision: 1354898 $ $Date: 2012-06-28 11:19:02 +0100 (Thu, 28 Jun 2012) $
 */
public class WSSSignatureEndingOutputProcessor extends AbstractSignatureEndingOutputProcessor {

    private static final List<QName> appendAfterOneOfThisAttributes;

    static {
        List<QName> list = new ArrayList<QName>(5);
        list.add(WSSConstants.ATT_wsu_Id);
        list.add(WSSConstants.ATT_NULL_Id);
        list.add(WSSConstants.ATT_NULL_AssertionID);
        list.add(WSSConstants.ATT_NULL_ID);
        appendAfterOneOfThisAttributes = Collections.unmodifiableList(list);
    }

    private SignedInfoProcessor signedInfoProcessor = null;

    public WSSSignatureEndingOutputProcessor(WSSSignatureOutputProcessor signatureOutputProcessor) throws XMLSecurityException {
        super(signatureOutputProcessor);
        this.addAfterProcessor(WSSSignatureOutputProcessor.class.getName());
        this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
    }

    @Override
    protected SignedInfoProcessor newSignedInfoProcessor(
            SignatureAlgorithm signatureAlgorithm, XMLSecStartElement xmlSecStartElement,
            OutputProcessorChain outputProcessorChain) throws XMLSecurityException {

        //we have to search for the SecurityHeaderElement for InclusiveNamespaces (same behavior as in wss-dom):
        while (!WSSConstants.TAG_wsse_Security.equals(xmlSecStartElement.getName())) {
            xmlSecStartElement = xmlSecStartElement.getParentXMLSecStartElement();
        }

        this.signedInfoProcessor = new SignedInfoProcessor(signatureAlgorithm, xmlSecStartElement);
        this.signedInfoProcessor.setXMLSecurityProperties(getSecurityProperties());
        this.signedInfoProcessor.setAction(getAction());
        this.signedInfoProcessor.addAfterProcessor(WSSSignatureEndingOutputProcessor.class.getName());
        this.signedInfoProcessor.init(outputProcessorChain);
        return this.signedInfoProcessor;
    }

    @Override
    public void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        super.processHeaderEvent(outputProcessorChain);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        signatureValueSecurityEvent.setSignatureValue(this.signedInfoProcessor.getSignatureValue());
        outputProcessorChain.getSecurityContext().registerSecurityEvent(signatureValueSecurityEvent);
    }

    @Override
    protected void createKeyInfoStructureForSignature(
            OutputProcessorChain outputProcessorChain,
            OutboundSecurityToken securityToken,
            boolean useSingleCertificate)
            throws XMLStreamException, XMLSecurityException {

        WSSConstants.KeyIdentifierType keyIdentifierType = getSecurityProperties().getSignatureKeyIdentifierType();

        X509Certificate[] x509Certificates = securityToken.getX509Certificates();

        if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.KEY_VALUE) {
            WSSUtils.createKeyValueTokenStructure(this, outputProcessorChain, x509Certificates);
        } else {
            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            } else if (WSSConstants.Saml10Token.equals(securityToken.getTokenType())
                    || WSSConstants.Saml11Token.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE));
            } else if (WSSConstants.Saml20Token.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE));
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            String tokenId = securityToken.getId();

            if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL) {
                createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SKI_KEY_IDENTIFIER) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                String valueType;
                if (useSingleCertificate) {
                    valueType = WSSConstants.NS_X509_V3_TYPE;
                } else {
                    valueType = WSSConstants.NS_X509PKIPathv1;
                }
                if (WSSConstants.Saml20Token.equals(securityToken.getTokenType())) {
                    valueType = null;
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.EMBEDDED_KEYIDENTIFIER_REF) {
                WSSUtils.createEmbeddedKeyIdentifierStructure(this, outputProcessorChain, securityToken.getTokenType(), tokenId);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.USERNAMETOKEN_REFERENCE) {
                WSSUtils.createUsernameTokenReferenceStructure(this, outputProcessorChain, tokenId);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "unsupportedSecurityToken");
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }
    }

    @Override
    protected void createTransformsStructureForSignature(OutputProcessorChain subOutputProcessorChain, SignaturePartDef signaturePartDef) throws XMLStreamException, XMLSecurityException {
        String[] transforms = signaturePartDef.getTransforms();
        if (transforms != null && transforms.length > 0) {
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transforms, false, null);

            if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(transforms[0])) {
                List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, transforms[0]));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform, false, attributes);
                if (transforms.length >= 2) {
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_TransformationParameters, false, null);
                    attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, transforms[1]));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_CanonicalizationMethod, false, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_CanonicalizationMethod);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_TransformationParameters);
                }
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform);
            } else {
                for (int i = 0; i < transforms.length; i++) {
                    String transform = transforms[i];

                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, transform));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform, false, attributes);

                    if (getSecurityProperties().isAddExcC14NInclusivePrefixes()) {
                        attributes = new ArrayList<XMLSecAttribute>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_PrefixList, signaturePartDef.getInclusiveNamespacesPrefixes()));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces, true, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                    }

                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform);
                }
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transforms);
        }
    }

    @Override
    protected List<QName> getAppendAfterOneOfThisAttributes() {
        return appendAfterOneOfThisAttributes;
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        setAppendAfterThisTokenId(outputProcessorChain.getSecurityContext().<String>get(XMLSecurityConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID));
        super.doFinal(outputProcessorChain);
    }

    @Override
    public void flushBufferAndCallbackAfterTokenID(OutputProcessorChain outputProcessorChain,
                                                   Deque<XMLSecEvent> xmlSecEventDeque)
            throws XMLStreamException, XMLSecurityException {

        final String actor = ((WSSSecurityProperties) getSecurityProperties()).getActor();

        //loop until we reach our security header
        loop:
        while (!xmlSecEventDeque.isEmpty()) {
            XMLSecEvent xmlSecEvent = xmlSecEventDeque.pop();
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                    if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                            && WSSUtils.isResponsibleActorOrRole(
                            xmlSecStartElement, actor)) {
                        outputProcessorChain.reset();
                        outputProcessorChain.processEvent(xmlSecEvent);
                        break loop;
                    }
                    break;
            }
            outputProcessorChain.reset();
            outputProcessorChain.processEvent(xmlSecEvent);
        }
        super.flushBufferAndCallbackAfterTokenID(outputProcessorChain, xmlSecEventDeque);
    }
}
