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

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.impl.securityToken.KerberosClientSecurityToken;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.List;

public class KerberosSecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public KerberosSecurityTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {
            XMLSecurityConstants.Action action = getAction();

            String tokenId = 
                outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_BST);
            KerberosClientSecurityToken kerberosToken = null;
            if (tokenId != null) {
                SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider = 
                    outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                kerberosToken = (KerberosClientSecurityToken)securityTokenProvider.getSecurityToken();
            }
            if (kerberosToken == null) {
                final String bstId = IDGenerator.generateID(null);
                final KerberosClientSecurityToken kerberosClientSecurityToken =
                        new KerberosClientSecurityToken(
                                ((WSSSecurityProperties) getSecurityProperties()).getCallbackHandler(),
                                bstId
                        );
    
                final SecurityTokenProvider<OutboundSecurityToken> kerberosSecurityTokenProvider =
                        new SecurityTokenProvider<OutboundSecurityToken>() {
    
                    @Override
                    public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                        return kerberosClientSecurityToken;
                    }
    
                    @Override
                    public String getId() {
                        return bstId;
                    }
                };
                
                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(bstId, kerberosSecurityTokenProvider);
                kerberosToken = kerberosClientSecurityToken;
                tokenId = bstId;
            }

            FinalKerberosSecurityTokenOutputProcessor finalKerberosSecurityTokenOutputProcessor =
                new FinalKerberosSecurityTokenOutputProcessor(kerberosToken);
            finalKerberosSecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalKerberosSecurityTokenOutputProcessor.setAction(getAction());
        
            if (WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(action)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, tokenId);
                finalKerberosSecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
            } else if (WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN.equals(action)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, tokenId);
                finalKerberosSecurityTokenOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
            }
            finalKerberosSecurityTokenOutputProcessor.init(outputProcessorChain);
            kerberosToken.setProcessor(finalKerberosSecurityTokenOutputProcessor);


        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalKerberosSecurityTokenOutputProcessor extends AbstractOutputProcessor {

        private final KerberosClientSecurityToken securityToken;

        FinalKerberosSecurityTokenOutputProcessor(KerberosClientSecurityToken securityToken) throws XMLSecurityException {
            super();
            this.addAfterProcessor(KerberosSecurityTokenOutputProcessor.class.getName());
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            outputProcessorChain.processEvent(xmlSecEvent);

            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

                final QName headerElementName = WSSConstants.TAG_wsse_BinarySecurityToken;
                WSSUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(3);
                attributes.add(createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
                attributes.add(createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_GSS_Kerberos5_AP_REQ));
                attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, securityToken.getId()));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, false, attributes);
                createCharactersAndOutputAsEvent(subOutputProcessorChain,
                        new Base64(76, new byte[]{'\n'}).encodeToString(securityToken.getTicket())
                );
                createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);
                if (WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN.equals(getAction())) {                    
                    WSSUtils.updateSecurityHeaderOrder(outputProcessorChain, WSSConstants.TAG_xenc_ReferenceList, getAction(), false);                    
                    WSSUtils.createReferenceListStructureForEncryption(this, subOutputProcessorChain);
                }
                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
