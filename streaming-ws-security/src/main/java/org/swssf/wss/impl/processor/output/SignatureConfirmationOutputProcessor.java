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
package org.swssf.wss.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignatureValueSecurityEvent;
import org.swssf.xmlsec.ext.AbstractOutputProcessor;
import org.swssf.xmlsec.ext.OutputProcessorChain;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.ext.stax.XMLSecAttribute;
import org.swssf.xmlsec.ext.stax.XMLSecEvent;
import org.swssf.xmlsec.ext.stax.XMLSecStartElement;
import org.swssf.xmlsec.impl.util.IDGenerator;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureConfirmationOutputProcessor extends AbstractOutputProcessor {

    public SignatureConfirmationOutputProcessor() throws XMLSecurityException {
        super();
        addBeforeProcessor(SignatureOutputProcessor.class.getName());
        addBeforeProcessor(EncryptOutputProcessor.class.getName());
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlSecEvent);
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
            if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                    && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                boolean aSignatureFound = false;

                List<SecurityEvent> requestSecurityEvents = outputProcessorChain.getSecurityContext().getAsList(SecurityEvent.class);
                for (int i = 0; i < requestSecurityEvents.size(); i++) {
                    SecurityEvent securityEvent = requestSecurityEvents.get(i);
                    if (securityEvent.getSecurityEventType() == SecurityEvent.Event.SignatureValue) {
                        aSignatureFound = true;
                        SignatureValueSecurityEvent signatureValueSecurityEvent = (SignatureValueSecurityEvent) securityEvent;

                        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
                        attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
                        attributes.add(createAttribute(WSSConstants.ATT_NULL_Value, new Base64(76, new byte[]{'\n'}).encodeToString(signatureValueSecurityEvent.getSignatureValue())));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation, true, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation);
                    }
                }

                if (!aSignatureFound) {
                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation, true, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation);
                }

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
