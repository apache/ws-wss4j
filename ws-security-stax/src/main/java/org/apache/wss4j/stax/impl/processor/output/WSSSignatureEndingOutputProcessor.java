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
package org.apache.wss4j.stax.impl.processor.output;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.impl.SecurityHeaderOrder;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.algorithms.SignatureAlgorithm;
import org.apache.xml.security.stax.impl.processor.output.AbstractSignatureEndingOutputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import java.security.cert.X509Certificate;
import java.security.Key;
import java.util.*;

public class WSSSignatureEndingOutputProcessor extends AbstractSignatureEndingOutputProcessor {

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

        if (securityToken.getCustomTokenReference() != null) {
            outputDOMElement(securityToken.getCustomTokenReference(), outputProcessorChain);
            return;
        }
        
        WSSecurityTokenConstants.KeyIdentifier keyIdentifier = getSecurityProperties().getSignatureKeyIdentifier();

        X509Certificate[] x509Certificates = securityToken.getX509Certificates();
        
        if (WSSecurityTokenConstants.KeyIdentifier_KeyValue.equals(keyIdentifier)) {
            WSSUtils.createKeyValueTokenStructure(this, outputProcessorChain, x509Certificates);
        } else {
            boolean isSAMLToken = false;
            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (WSSecurityTokenConstants.Saml10Token.equals(securityToken.getTokenType())
                || WSSecurityTokenConstants.Saml11Token.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE));
                isSAMLToken = true;
            } else if (WSSecurityTokenConstants.Saml20Token.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE));
                isSAMLToken = true;
            } else if (WSSecurityTokenConstants.KerberosToken.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_GSS_Kerberos5_AP_REQ));
            } else if (WSSecurityTokenConstants.EncryptedKeyToken.equals(securityToken.getTokenType())
                || WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier.equals(keyIdentifier)
                || WSSecurityTokenConstants.KeyIdentifier_EncryptedKey.equals(keyIdentifier)) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_WSS_ENC_KEY_VALUE_TYPE));
            } else if (WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(keyIdentifier) && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            } 
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            String tokenId = securityToken.getId();

            if (isSAMLToken) {
                // Always use KeyIdentifier regardless of the configured KeyIdentifier value
                WSSUtils.createSAMLKeyIdentifierStructure(this, outputProcessorChain, securityToken.getTokenType(), tokenId);
            } else if (WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier.equals(keyIdentifier)) {
                String identifier = securityToken.getSha1Identifier();
                if (identifier != null) {
                    WSSUtils.createEncryptedKeySha1IdentifierStructure(this, outputProcessorChain, identifier);
                } else {
                    Key key = securityToken.getSecretKey(getSecurityProperties().getSignatureAlgorithm());
                    WSSUtils.createEncryptedKeySha1IdentifierStructure(this, outputProcessorChain, key);
                }
            } else if (WSSecurityTokenConstants.KeyIdentifier_KerberosSha1Identifier.equals(keyIdentifier)) {
                String identifier = securityToken.getSha1Identifier();
                WSSUtils.createKerberosSha1IdentifierStructure(this, outputProcessorChain, identifier);
            } else if (WSSecurityTokenConstants.EncryptedKeyToken.equals(securityToken.getTokenType())
                || WSSecurityTokenConstants.KeyIdentifier_EncryptedKey.equals(keyIdentifier)) {
                String id = securityToken.getId();
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, id, WSSConstants.NS_WSS_ENC_KEY_VALUE_TYPE, true);
            } else if (WSSecurityTokenConstants.KeyIdentifier_IssuerSerial.equals(keyIdentifier)) {
                WSSUtils.createX509IssuerSerialStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier.equals(keyIdentifier)) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier.equals(keyIdentifier)) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier.equals(keyIdentifier)) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(keyIdentifier)) {
                String valueType;
                boolean included = true;
                if (WSSecurityTokenConstants.Saml20Token.equals(securityToken.getTokenType())) {
                    valueType = null;
                } else if (WSSecurityTokenConstants.KerberosToken.equals(securityToken.getTokenType())) {
                    valueType = WSSConstants.NS_GSS_Kerberos5_AP_REQ;
                } else if (WSSecurityTokenConstants.DerivedKeyToken.equals(securityToken.getTokenType())) {
                    boolean use200512Namespace = ((WSSSecurityProperties)getSecurityProperties()).isUse200512Namespace();
                    if (use200512Namespace) {
                        valueType = WSSConstants.NS_WSC_05_12 + "/dk";
                    } else {
                        valueType = WSSConstants.NS_WSC_05_02 + "/dk";
                    }
                } else if (WSSecurityTokenConstants.SpnegoContextToken.equals(securityToken.getTokenType())
                    || WSSecurityTokenConstants.SecurityContextToken.equals(securityToken.getTokenType())
                    || WSSecurityTokenConstants.SecureConversationToken.equals(securityToken.getTokenType())) {
                    boolean use200512Namespace = ((WSSSecurityProperties)getSecurityProperties()).isUse200512Namespace();
                    if (use200512Namespace) {
                        valueType = WSSConstants.NS_WSC_05_12 + "/sct";
                    } else {
                        valueType = WSSConstants.NS_WSC_05_02 + "/sct";
                    }
                    included = ((WSSSecurityProperties)getSecurityProperties()).isIncludeSignatureToken();
                } else {
                    if (useSingleCertificate) {
                        valueType = WSSConstants.NS_X509_V3_TYPE;
                    } else {
                        valueType = WSSConstants.NS_X509PKIPathv1;
                    }
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType, included);
            } else if (WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef.equals(keyIdentifier)) {
                WSSUtils.createEmbeddedKeyIdentifierStructure(this, outputProcessorChain, securityToken.getTokenType(), tokenId);
            } else if (WSSecurityTokenConstants.KeyIdentifier_UsernameTokenReference.equals(keyIdentifier)) {
                WSSUtils.createUsernameTokenReferenceStructure(this, outputProcessorChain, tokenId);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "unsupportedSecurityToken", 
                                              new Object[] {keyIdentifier});
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

                    if (getSecurityProperties().isAddExcC14NInclusivePrefixes()
                            && !WSSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS.equals(transform)
                            && !WSSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS.equals(transform))
                    {
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
    public void flushBufferAndCallbackAfterHeader(OutputProcessorChain outputProcessorChain,
                                                   Deque<XMLSecEvent> xmlSecEventDeque)
            throws XMLStreamException, XMLSecurityException {

        final String actor = ((WSSSecurityProperties) getSecurityProperties()).getActor();

        //loop until we reach our security header
        loop:
        while (!xmlSecEventDeque.isEmpty()) {
            XMLSecEvent xmlSecEvent = xmlSecEventDeque.pop();
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, actor)) {
                        
                        WSSUtils.updateSecurityHeaderOrder(
                                outputProcessorChain, WSSConstants.TAG_dsig_Signature, getAction(), true);
                        
                        List<SecurityHeaderOrder> securityHeaderOrderList = 
                                outputProcessorChain.getSecurityContext().getAsList(SecurityHeaderOrder.class);
                        List<SecurityHeaderOrder> tmpList = null;
                        if (securityHeaderOrderList != null) {
                            tmpList = new ArrayList<SecurityHeaderOrder>(securityHeaderOrderList);
                            securityHeaderOrderList.clear();
                        }
                        
                        outputProcessorChain.reset();
                        outputProcessorChain.processEvent(xmlSecEvent);

                        if (securityHeaderOrderList != null) {
                            securityHeaderOrderList.addAll(tmpList);
                        }
                        break loop;
                    }
                    break;
            }
            outputProcessorChain.reset();
            outputProcessorChain.processEvent(xmlSecEvent);
        }
        super.flushBufferAndCallbackAfterHeader(outputProcessorChain, xmlSecEventDeque);
    }
}
