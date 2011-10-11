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

import org.swssf.wss.ext.*;
import org.swssf.xmlsec.ext.AbstractOutputProcessor;
import org.swssf.xmlsec.ext.OutputProcessorChain;
import org.swssf.xmlsec.ext.SecurePart;
import org.swssf.xmlsec.ext.XMLSecurityException;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Processor to build the Security Header structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityHeaderOutputProcessor extends AbstractOutputProcessor {

    public SecurityHeaderOutputProcessor(WSSSecurityProperties securityProperties, WSSConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
        setPhase(WSSConstants.Phase.PREPROCESSING);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        boolean eventHandled = false;
        int level = outputProcessorChain.getDocumentContext().getDocumentLevel();

        String soapMessageVersion = ((WSSDocumentContext) outputProcessorChain.getDocumentContext()).getSOAPMessageVersionNamespace();

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (level == 1 && soapMessageVersion == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "notASOAPMessage");
            } else if (level == 1 && soapMessageVersion != null) {
                //set correct namespace on secure parts
                List<SecurePart> securePartList = securityProperties.getEncryptionSecureParts();
                for (int i = 0; i < securePartList.size(); i++) {
                    SecurePart securePart = securePartList.get(i);
                    if (securePart.getName().equals("Body") && securePart.getNamespace().equals("*")) {
                        securePart.setNamespace(soapMessageVersion);
                        break;
                    }
                }
                securePartList = securityProperties.getSignatureSecureParts();
                for (int j = 0; j < securePartList.size(); j++) {
                    SecurePart securePart = securePartList.get(j);
                    if (securePart.getName().equals("Body") && securePart.getNamespace().equals("*")) {
                        securePart.setNamespace(soapMessageVersion);
                    }
                }
            } else if (level == 3 && startElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                if (WSSUtils.isResponsibleActorOrRole(startElement, soapMessageVersion, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    ((WSSDocumentContext) outputProcessorChain.getDocumentContext()).setInSecurityHeader(true);
                    //remove this processor. its no longer needed.
                    outputProcessorChain.removeProcessor(this);
                }
            } else if (level == 2
                    && startElement.getName().getLocalPart().equals(WSSConstants.TAG_soap_Body_LocalName)
                    && startElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                //hmm it seems we don't have a soap header in the current document
                //so output one and add securityHeader

                //create subchain and output soap-header and securityHeader
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                createStartElementAndOutputAsEvent(subOutputProcessorChain,
                        new QName(soapMessageVersion, WSSConstants.TAG_soap_Header_LocalName, WSSConstants.PREFIX_SOAPENV), null);
                buildSecurityHeader(soapMessageVersion, subOutputProcessorChain);
                createEndElementAndOutputAsEvent(subOutputProcessorChain,
                        new QName(soapMessageVersion, WSSConstants.TAG_soap_Header_LocalName, WSSConstants.PREFIX_SOAPENV));

                //output current soap-header event
                outputProcessorChain.processEvent(xmlEvent);
                //remove this processor. its no longer needed.
                outputProcessorChain.removeProcessor(this);

                eventHandled = true;
            }
        } else if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (level == 2 && endElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                ((WSSDocumentContext) outputProcessorChain.getDocumentContext()).setInSecurityHeader(false);
            } else if (level == 1 && endElement.getName().getLocalPart().equals(WSSConstants.TAG_soap_Header_LocalName)
                    && endElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                buildSecurityHeader(soapMessageVersion, subOutputProcessorChain);
                //output current soap-header event
                outputProcessorChain.processEvent(xmlEvent);
                //remove this processor. its no longer needed.
                outputProcessorChain.removeProcessor(this);

                eventHandled = true;
            }
        }

        if (!eventHandled) {
            outputProcessorChain.processEvent(xmlEvent);
        }
    }

    private void buildSecurityHeader(String soapMessageVersion, OutputProcessorChain subOutputProcessorChain) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        final String actor = ((WSSSecurityProperties) getSecurityProperties()).getActor();
        if (actor != null && !"".equals(actor)) {
            if (WSSConstants.NS_SOAP11.equals(soapMessageVersion)) {
                attributes.put(WSSConstants.ATT_soap11_Actor, actor);
            } else {
                attributes.put(WSSConstants.ATT_soap12_Role, actor);
            }
        }
        ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).setInSecurityHeader(true);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Security, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Security);
        ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).setInSecurityHeader(false);
    }
}
