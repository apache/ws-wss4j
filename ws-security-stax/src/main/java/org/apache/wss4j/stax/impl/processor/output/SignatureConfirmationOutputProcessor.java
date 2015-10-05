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

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;

public class SignatureConfirmationOutputProcessor extends AbstractOutputProcessor {

    public SignatureConfirmationOutputProcessor() throws XMLSecurityException {
        super();
        addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
        addBeforeProcessor(EncryptOutputProcessor.class.getName());
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException {

        outputProcessorChain.processEvent(xmlSecEvent);

        if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

            final QName headerElementName = WSSConstants.TAG_wsse11_SignatureConfirmation;

            OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

            boolean aSignatureFound = false;

            List<SecurityEvent> requestSecurityEvents = outputProcessorChain.getSecurityContext().getAsList(SecurityEvent.class);
            for (int i = 0; i < requestSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = requestSecurityEvents.get(i);
                if (SecurityEventConstants.SignatureValue.equals(securityEvent.getSecurityEventType())) {
                    aSignatureFound = true;
                    SignatureValueSecurityEvent signatureValueSecurityEvent = (SignatureValueSecurityEvent) securityEvent;

                    OutputProcessorUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);

                    List<XMLSecAttribute> attributes = new ArrayList<>(2);
                    attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Value, new Base64(76, new byte[]{'\n'}).encodeToString(signatureValueSecurityEvent.getSignatureValue())));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, true, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);
                }
            }

            if (!aSignatureFound) {
                OutputProcessorUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);
                List<XMLSecAttribute> attributes = new ArrayList<>(1);
                attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, true, attributes);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);
            }

            outputProcessorChain.removeProcessor(this);
        }
    }
}
