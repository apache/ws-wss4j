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

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.KerberosClientSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;
import org.apache.xml.security.utils.XMLUtils;

public class BinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public BinarySecurityTokenOutputProcessor() throws XMLSecurityException {
        super();
        addBeforeProcessor(WSSSignatureOutputProcessor.class);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
        throws XMLStreamException, XMLSecurityException {
        try {
            GenericOutboundSecurityToken securityToken = null;

            XMLSecurityConstants.Action action = getAction();
            String tokenId = null;
            if (WSSConstants.SIGNATURE.equals(action)
                    || WSSConstants.SAML_TOKEN_SIGNED.equals(action)) {
                tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
            } else if (WSSConstants.ENCRYPTION.equals(action)) {
                tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
            } else if (WSSConstants.ENCRYPTION_WITH_KERBEROS_TOKEN.equals(getAction())
                || WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(getAction())
                || WSSConstants.KERBEROS_TOKEN.equals(getAction())) {
                tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_KERBEROS);
            }

            SecurityTokenProvider<OutboundSecurityToken> tokenProvider = null;
            if (tokenId != null) {
                tokenProvider =
                    outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                if (tokenProvider != null) {
                    securityToken = (GenericOutboundSecurityToken)tokenProvider.getSecurityToken();
                }
            }

            boolean includeToken = false;
            WSSecurityTokenConstants.KeyIdentifier keyIdentifier = null;
            if ((WSSConstants.SIGNATURE.equals(action) || WSSConstants.SAML_TOKEN_SIGNED.equals(action))
                && !getSecurityProperties().getSignatureKeyIdentifiers().isEmpty()) {
                includeToken = ((WSSSecurityProperties) getSecurityProperties()).isIncludeSignatureToken();
                keyIdentifier = getSecurityProperties().getSignatureKeyIdentifiers().get(0);
            } else if (WSSConstants.ENCRYPTION.equals(action)) {
                includeToken = ((WSSSecurityProperties) getSecurityProperties()).isIncludeEncryptionToken();
                keyIdentifier = getSecurityProperties().getEncryptionKeyIdentifier();
            }

            if (securityToken != null) {
                if (WSSConstants.SIGNATURE.equals(action)
                    && (includeToken || WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE.equals(keyIdentifier))
                    && (securityToken.getTokenType() == null
                    || WSSecurityTokenConstants.X509V3Token.equals(securityToken.getTokenType()))) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor =
                        new FinalBinarySecurityTokenOutputProcessor(securityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction(), getActionOrder());
                    finalBinarySecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class);
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    securityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                } else if (WSSConstants.SAML_TOKEN_SIGNED.equals(action) && includeToken
                    && (securityToken.getTokenType() == null
                        || WSSecurityTokenConstants.X509V3Token.equals(securityToken.getTokenType()))) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor =
                        new FinalBinarySecurityTokenOutputProcessor(securityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction(), getActionOrder());
                    finalBinarySecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class);
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    securityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                } else if (WSSConstants.ENCRYPTION.equals(action)
                    && (includeToken || WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE.equals(keyIdentifier))
                    && (securityToken.getTokenType() == null
                        || WSSecurityTokenConstants.X509V3Token.equals(securityToken.getTokenType()))) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor =
                        new FinalBinarySecurityTokenOutputProcessor(securityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction(), getActionOrder());
                    finalBinarySecurityTokenOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class);
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    securityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                } else if (WSSConstants.ENCRYPTION_WITH_KERBEROS_TOKEN.equals(getAction())
                    || WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(getAction())
                    || WSSConstants.KERBEROS_TOKEN.equals(getAction())) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor =
                        new FinalBinarySecurityTokenOutputProcessor(securityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction(), getActionOrder());
                    finalBinarySecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class);
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    securityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                }
            }
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    static class FinalBinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;

        FinalBinarySecurityTokenOutputProcessor(OutboundSecurityToken securityToken) throws XMLSecurityException {
            super();
            this.addAfterProcessor(BinarySecurityTokenOutputProcessor.class);
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            outputProcessorChain.processEvent(xmlSecEvent);

            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

                final QName headerElementName = WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN;

                if (WSSConstants.ENCRYPTION_WITH_KERBEROS_TOKEN.equals(getAction())
                    || WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(getAction())
                    || WSSConstants.KERBEROS_TOKEN.equals(getAction())) {
                    OutputProcessorUtils.updateSecurityHeaderOrder(
                        outputProcessorChain, headerElementName, getAction(), false);
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    List<XMLSecAttribute> attributes = new ArrayList<>(3);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_ENCODING_TYPE, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_VALUE_TYPE, WSSConstants.NS_GSS_KERBEROS5_AP_REQ));
                    attributes.add(createAttribute(WSSConstants.ATT_WSU_ID, securityToken.getId()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, false, attributes);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain,
                            XMLUtils.encodeToString(
                                ((KerberosClientSecurityToken)securityToken).getTicket())
                    );
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);
                    if (WSSConstants.ENCRYPTION_WITH_KERBEROS_TOKEN.equals(getAction())) {
                        OutputProcessorUtils.updateSecurityHeaderOrder(outputProcessorChain, WSSConstants.TAG_xenc_ReferenceList,
                                                                       getAction(), false);
                        WSSUtils.createReferenceListStructureForEncryption(this, subOutputProcessorChain);
                    }
                } else if (securityToken.getX509Certificates() != null
                    && securityToken.getX509Certificates().length > 0) {
                    OutputProcessorUtils.updateSecurityHeaderOrder(
                        outputProcessorChain, headerElementName, getAction(), false);
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    boolean useSingleCertificate = getSecurityProperties().isUseSingleCert();
                    WSSUtils.createBinarySecurityTokenStructure(
                            this, subOutputProcessorChain, securityToken.getId(),
                            securityToken.getX509Certificates(), useSingleCertificate);
                }

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
