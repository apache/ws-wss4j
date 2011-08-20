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

import org.swssf.ext.*;

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

    public SecurityHeaderOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
        setPhase(Constants.Phase.PREPROCESSING);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        boolean eventHandled = false;
        int level = outputProcessorChain.getDocumentContext().getDocumentLevel();

        String soapMessageVersion = outputProcessorChain.getDocumentContext().getSOAPMessageVersionNamespace();

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
            } else if (level == 3 && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                if (Utils.isResponsibleActorOrRole(startElement, soapMessageVersion, getSecurityProperties().getActor())) {
                    outputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                    //remove this processor. its no longer needed.
                    outputProcessorChain.removeProcessor(this);
                }
            } else if (level == 2
                    && startElement.getName().getLocalPart().equals(Constants.TAG_soap_Body_LocalName)
                    && startElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                //hmm it seems we don't have a soap header in the current document
                //so output one and add securityHeader

                //create subchain and output soap-header and securityHeader
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                createStartElementAndOutputAsEvent(subOutputProcessorChain,
                        new QName(soapMessageVersion, Constants.TAG_soap_Header_LocalName, Constants.PREFIX_SOAPENV), null);
                buildSecurityHeader(soapMessageVersion, subOutputProcessorChain);
                createEndElementAndOutputAsEvent(subOutputProcessorChain,
                        new QName(soapMessageVersion, Constants.TAG_soap_Header_LocalName, Constants.PREFIX_SOAPENV));

                //output current soap-header event
                outputProcessorChain.processEvent(xmlEvent);
                //remove this processor. its no longer needed.
                outputProcessorChain.removeProcessor(this);

                eventHandled = true;
            }
        } else if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (level == 2 && endElement.getName().equals(Constants.TAG_wsse_Security)) {
                outputProcessorChain.getDocumentContext().setInSecurityHeader(false);
            } else if (level == 1 && endElement.getName().getLocalPart().equals(Constants.TAG_soap_Header_LocalName)
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

    private void buildSecurityHeader(String soapMessageVersion, OutputProcessorChain subOutputProcessorChain) throws XMLStreamException, WSSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        final String actor = getSecurityProperties().getActor();
        if (actor != null && !"".equals(actor)) {
            if (Constants.NS_SOAP11.equals(soapMessageVersion)) {
                attributes.put(Constants.ATT_soap11_Actor, actor);
            } else {
                attributes.put(Constants.ATT_soap12_Role, actor);
            }
        }
        subOutputProcessorChain.getDocumentContext().setInSecurityHeader(true);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security);
        subOutputProcessorChain.getDocumentContext().setInSecurityHeader(false);
    }
}
