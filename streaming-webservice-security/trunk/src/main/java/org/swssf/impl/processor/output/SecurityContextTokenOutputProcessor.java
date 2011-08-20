/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.output;

import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.ProcessorInfoSecurityToken;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityContextTokenOutputProcessor extends AbstractOutputProcessor {

    public SecurityContextTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        try {
            String tokenId = outputProcessorChain.getSecurityContext().get(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            final SecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken(null);
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }

            final String wsuId = "SCT-" + UUID.randomUUID().toString();
            final String identifier = UUID.randomUUID().toString();

            final ProcessorInfoSecurityToken securityContextSecurityToken = new ProcessorInfoSecurityToken() {

                private OutputProcessor outputProcessor;

                public String getId() {
                    return wsuId;
                }

                public void setProcessor(OutputProcessor outputProcessor) {
                    this.outputProcessor = outputProcessor;
                }

                public Object getProcessor() {
                    return outputProcessor;
                }

                public boolean isAsymmetric() {
                    return wrappingSecurityToken.isAsymmetric();
                }

                public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
                    return wrappingSecurityToken.getSecretKey(algorithmURI, keyUsage);
                }

                public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
                    return wrappingSecurityToken.getPublicKey(keyUsage);
                }

                public X509Certificate[] getX509Certificates() throws WSSecurityException {
                    return wrappingSecurityToken.getX509Certificates();
                }

                public void verify() throws WSSecurityException {
                    wrappingSecurityToken.verify();
                }

                public SecurityToken getKeyWrappingToken() {
                    return wrappingSecurityToken;
                }

                public String getKeyWrappingTokenAlgorithm() {
                    return null;
                }

                public Constants.TokenType getTokenType() {
                    return Constants.TokenType.SecurityContextToken;
                }
            };

            SecurityTokenProvider securityContextSecurityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                    return securityContextSecurityToken;
                }

                public String getId() {
                    return wsuId;
                }
            };

            FinalSecurityContextTokenOutputProcessor finalSecurityContextTokenOutputProcessor = new FinalSecurityContextTokenOutputProcessor(getSecurityProperties(), getAction(), securityContextSecurityToken, identifier);
            switch (getAction()) {
                case SIGNATURE_WITH_DERIVED_KEY:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, wsuId);
                    if (wrappingSecurityToken.getProcessor() != null) {
                        finalSecurityContextTokenOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                    } else {
                        finalSecurityContextTokenOutputProcessor.getBeforeProcessors().add(SignatureOutputProcessor.class.getName());
                    }
                    break;
                case ENCRYPT_WITH_DERIVED_KEY:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, wsuId);
                    if (wrappingSecurityToken.getProcessor() != null) {
                        finalSecurityContextTokenOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                    } else {
                        finalSecurityContextTokenOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                    }
                    break;
            }

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(wsuId, securityContextSecurityTokenProvider);
            securityContextSecurityToken.setProcessor(finalSecurityContextTokenOutputProcessor);
            outputProcessorChain.addProcessor(finalSecurityContextTokenOutputProcessor);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    class FinalSecurityContextTokenOutputProcessor extends AbstractOutputProcessor {

        private SecurityToken securityToken;
        private String identifier;

        FinalSecurityContextTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action, SecurityToken securityToken, String identifier) throws WSSecurityException {
            super(securityProperties, action);
            this.securityToken = securityToken;
            this.identifier = identifier;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_wsu_Id, securityToken.getId());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsc0502_SecurityContextToken, attributes);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsc0502_Identifier, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, identifier);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsc0502_Identifier);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsc0502_SecurityContextToken);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
