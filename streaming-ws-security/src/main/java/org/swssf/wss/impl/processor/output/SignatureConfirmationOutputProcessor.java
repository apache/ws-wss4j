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
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignatureValueSecurityEvent;
import org.swssf.xmlsec.ext.AbstractOutputProcessor;
import org.swssf.xmlsec.ext.OutputProcessorChain;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.impl.util.IDGenerator;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
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
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlEvent);
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (((WSSDocumentContext) outputProcessorChain.getDocumentContext()).isInSecurityHeader() && startElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                boolean aSignatureFound = false;

                List<SecurityEvent> requestSecurityEvents = outputProcessorChain.getSecurityContext().getAsList(SecurityEvent.class);
                for (int i = 0; i < requestSecurityEvents.size(); i++) {
                    SecurityEvent securityEvent = requestSecurityEvents.get(i);
                    if (securityEvent.getSecurityEventType() == SecurityEvent.Event.SignatureValue) {
                        aSignatureFound = true;
                        SignatureValueSecurityEvent signatureValueSecurityEvent = (SignatureValueSecurityEvent) securityEvent;

                        List<Attribute> attributes = new ArrayList<Attribute>(2);
                        attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
                        attributes.add(createAttribute(WSSConstants.ATT_NULL_Value, new Base64(76, new byte[]{'\n'}).encodeToString(signatureValueSecurityEvent.getSignatureValue())));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation, true, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation);
                    }
                }

                if (!aSignatureFound) {
                    List<Attribute> attributes = new ArrayList<Attribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation, true, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse11_SignatureConfirmation);
                }

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
