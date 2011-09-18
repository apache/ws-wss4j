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
package org.swssf.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignatureTokenSecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureConfirmationOutputProcessor extends AbstractOutputProcessor {

    public SignatureConfirmationOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
        getBeforeProcessors().add(SignatureOutputProcessor.class.getName());
        getBeforeProcessors().add(EncryptOutputProcessor.class.getName());
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.processEvent(xmlEvent);
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                boolean aSignatureFound = false;

                List<SecurityEvent> requestSecurityEvents = outputProcessorChain.getSecurityContext().getAsList(SecurityEvent.class);
                for (int i = 0; i < requestSecurityEvents.size(); i++) {
                    SecurityEvent securityEvent = requestSecurityEvents.get(i);
                    if (securityEvent.getSecurityEventType() == SecurityEvent.Event.SignatureToken) {
                        aSignatureFound = true;
                        SignatureTokenSecurityEvent signatureTokenSecurityEvent = (SignatureTokenSecurityEvent) securityEvent;

                        Map<QName, String> attributes = new HashMap<QName, String>();
                        attributes.put(Constants.ATT_wsu_Id, "SigConf-" + UUID.randomUUID().toString());
                        attributes.put(Constants.ATT_NULL_Value, new Base64(76, new byte[]{'\n'}).encodeToString(signatureTokenSecurityEvent.getSignatureValue()));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation);
                    }
                }

                if (!aSignatureFound) {
                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_wsu_Id, "SigConf-" + UUID.randomUUID().toString());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation);
                }

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
