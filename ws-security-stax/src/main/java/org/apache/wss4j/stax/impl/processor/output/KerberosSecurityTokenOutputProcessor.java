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
import org.apache.xml.security.stax.ext.SecurityTokenProvider;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.stream.XMLStreamConstants;
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
            final String bstId = IDGenerator.generateID(null);

            XMLSecurityConstants.Action action = getAction();

            final KerberosClientSecurityToken kerberosClientSecurityToken =
                    new KerberosClientSecurityToken(
                            ((WSSSecurityProperties) getSecurityProperties()).getCallbackHandler(),
                            bstId
                    );


            final SecurityTokenProvider kerberosSecurityTokenProvider = new SecurityTokenProvider() {

                @SuppressWarnings("unchecked")
                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return kerberosClientSecurityToken;
                }

                @Override
                public String getId() {
                    return bstId;
                }
            };

            if (action.equals(WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, bstId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, bstId);
                FinalKerberosSecurityTokenOutputProcessor finalKerberosSecurityTokenOutputProcessor =
                        new FinalKerberosSecurityTokenOutputProcessor(kerberosClientSecurityToken);
                finalKerberosSecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                finalKerberosSecurityTokenOutputProcessor.setAction(getAction());
                finalKerberosSecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                finalKerberosSecurityTokenOutputProcessor.init(outputProcessorChain);
                kerberosClientSecurityToken.setProcessor(finalKerberosSecurityTokenOutputProcessor);
            } else if (action.equals(WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, bstId);
                FinalKerberosSecurityTokenOutputProcessor finalKerberosSecurityTokenOutputProcessor =
                        new FinalKerberosSecurityTokenOutputProcessor(kerberosClientSecurityToken);
                finalKerberosSecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                finalKerberosSecurityTokenOutputProcessor.setAction(getAction());
                finalKerberosSecurityTokenOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                finalKerberosSecurityTokenOutputProcessor.init(outputProcessorChain);
                kerberosClientSecurityToken.setProcessor(finalKerberosSecurityTokenOutputProcessor);
            }

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(bstId, kerberosSecurityTokenProvider);

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
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlSecEvent);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(3);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_GSS_Kerberos5_AP_REQ));
                    attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, securityToken.getId()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken, false, attributes);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain,
                            new Base64(76, new byte[]{'\n'}).encodeToString(securityToken.getTicket())
                    );
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken);
                    if (getAction() == WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN) {
                        WSSUtils.createReferenceListStructureForEncryption(this, subOutputProcessorChain);
                    }
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
