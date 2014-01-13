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
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class SecurityContextTokenOutputProcessor extends AbstractOutputProcessor {

    public SecurityContextTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        try {
            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            SecurityTokenProvider<OutboundSecurityToken> wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            final OutboundSecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken();
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            final String wsuId = IDGenerator.generateID(null);
            final String identifier = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken securityContextSecurityToken = new GenericOutboundSecurityToken(wsuId, WSSecurityTokenConstants.SecurityContextToken) {

                @Override
                public Key getSecretKey(String algorithmURI) throws XMLSecurityException {
                    return wrappingSecurityToken.getSecretKey(algorithmURI);
                }

                @Override
                public PublicKey getPublicKey() throws XMLSecurityException {
                    return wrappingSecurityToken.getPublicKey();
                }

                @Override
                public X509Certificate[] getX509Certificates() throws XMLSecurityException {
                    return wrappingSecurityToken.getX509Certificates();
                }
            };
            wrappingSecurityToken.addWrappedToken(securityContextSecurityToken);

            SecurityTokenProvider<OutboundSecurityToken> securityContextSecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return securityContextSecurityToken;
                }

                @Override
                public String getId() {
                    return wsuId;
                }
            };

            FinalSecurityContextTokenOutputProcessor finalSecurityContextTokenOutputProcessor =
                    new FinalSecurityContextTokenOutputProcessor(securityContextSecurityToken, identifier);
            finalSecurityContextTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalSecurityContextTokenOutputProcessor.setAction(getAction());
            XMLSecurityConstants.Action action = getAction();
            if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, wsuId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalSecurityContextTokenOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                } else {
                    finalSecurityContextTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                }
            } else if (WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, wsuId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalSecurityContextTokenOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                } else {
                    finalSecurityContextTokenOutputProcessor.addAfterProcessor(ReferenceListOutputProcessor.class.getName());
                    finalSecurityContextTokenOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                }
            }

            finalSecurityContextTokenOutputProcessor.init(outputProcessorChain);
            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(wsuId, securityContextSecurityTokenProvider);
            securityContextSecurityToken.setProcessor(finalSecurityContextTokenOutputProcessor);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalSecurityContextTokenOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;
        private final String identifier;

        FinalSecurityContextTokenOutputProcessor(OutboundSecurityToken securityToken, String identifier) throws XMLSecurityException {
            super();
            this.securityToken = securityToken;
            this.identifier = identifier;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            outputProcessorChain.processEvent(xmlSecEvent);

            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

                final QName headerElementName = WSSConstants.TAG_wsc0502_SecurityContextToken;
                WSSUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, securityToken.getId()));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, true, attributes);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Identifier, false, null);
                createCharactersAndOutputAsEvent(subOutputProcessorChain, identifier);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsc0502_Identifier);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
