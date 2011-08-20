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
package org.swssf.ext;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;
import java.util.Iterator;

/**
 * An abstract OutputProcessor class for reusabilty
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractBufferingOutputProcessor extends AbstractOutputProcessor {

    private ArrayDeque<XMLEvent> xmlEventBuffer = new ArrayDeque<XMLEvent>();
    private String appendAfterThisTokenId;

    protected AbstractBufferingOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    protected String getAppendAfterThisTokenId() {
        return appendAfterThisTokenId;
    }

    protected void setAppendAfterThisTokenId(String appendAfterThisTokenId) {
        this.appendAfterThisTokenId = appendAfterThisTokenId;
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        xmlEventBuffer.push(xmlEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        //loop until we reach our security header and set flag
        Iterator<XMLEvent> xmlEventIterator = xmlEventBuffer.descendingIterator();
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (startElement.getName().equals(Constants.TAG_wsse_Security)
                        && Utils.isResponsibleActorOrRole(
                        startElement,
                        subOutputProcessorChain.getDocumentContext().getSOAPMessageVersionNamespace(),
                        getSecurityProperties().getActor())) {
                    subOutputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    break;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }

        //append current header
        if (getAppendAfterThisTokenId() == null) {
            processHeaderEvent(subOutputProcessorChain);
        } else {
            //we have a dependent token. so we have to append the current header after the token
            boolean found = false;
            while (xmlEventIterator.hasNext() && !found) {
                XMLEvent xmlEvent = xmlEventIterator.next();

                subOutputProcessorChain.reset();
                subOutputProcessorChain.processEvent(xmlEvent);

                //search for an element with a matching wsu:Id. this is our token
                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    QName matchingElementName;

                    @SuppressWarnings("unchecked")
                    Iterator<Attribute> attributeIterator = startElement.getAttributes();
                    while (attributeIterator.hasNext() && !found) {
                        Attribute attribute = attributeIterator.next();
                        final QName attributeName = attribute.getName();
                        final String attributeValue = attribute.getValue();
                        if ((Constants.ATT_wsu_Id.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (Constants.ATT_NULL_Id.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (Constants.ATT_NULL_AssertionID.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (Constants.ATT_NULL_ID.equals(attributeName) && getAppendAfterThisTokenId().endsWith(attributeValue))) {
                            matchingElementName = startElement.getName();
                            //we found the token and...
                            int level = 0;
                            while (xmlEventIterator.hasNext() && !found) {
                                xmlEvent = xmlEventIterator.next();

                                subOutputProcessorChain.reset();
                                subOutputProcessorChain.processEvent(xmlEvent);

                                //loop until we reach the token end element
                                if (xmlEvent.isEndElement()) {
                                    EndElement endElement = xmlEvent.asEndElement();
                                    if (level == 0 && endElement.getName().equals(matchingElementName)) {
                                        found = true;
                                        //output now the current header
                                        processHeaderEvent(subOutputProcessorChain);
                                    }
                                    level--;
                                } else if (xmlEvent.isStartElement()) {
                                    level++;
                                }
                            }
                        }
                    }
                }
            }
        }
        //loop until our security header end element and unset the flag
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(Constants.TAG_wsse_Security)) {
                    subOutputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    break;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        //loop throug the rest of the document
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        subOutputProcessorChain.reset();
        //call final on the rest of the chain
        subOutputProcessorChain.doFinal();
        //this processor is now finished and we can remove it now
        subOutputProcessorChain.removeProcessor(this);
    }

    protected abstract void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException;
}
