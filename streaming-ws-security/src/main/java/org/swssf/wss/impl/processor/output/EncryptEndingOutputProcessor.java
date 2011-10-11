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

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.xmlsec.ext.OutputProcessorChain;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.impl.processor.output.AbstractEncryptEndingOutputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Iterator;

/**
 * Processor buffers encrypted XMLEvents and forwards them when final is called
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptEndingOutputProcessor extends AbstractEncryptEndingOutputProcessor {

    public EncryptEndingOutputProcessor(WSSSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
        this.getAfterProcessors().add(EncryptOutputProcessor.class.getName());
        this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
    }

    @Override
    protected void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
        if (getAction() == WSSConstants.ENCRYPT_WITH_DERIVED_KEY) {
            createReferenceListStructure(subOutputProcessorChain);
        }
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //todo replace this and in EncryptEndingOutputProcessor with a common method somewhere
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        //loop until we reach our security header and set flag
        Iterator<XMLEvent> xmlEventIterator = getXmlEventBuffer().descendingIterator();
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (startElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isResponsibleActorOrRole(
                        startElement,
                        ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).getSOAPMessageVersionNamespace(),
                        ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).setInSecurityHeader(true);
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
                        if ((WSSConstants.ATT_wsu_Id.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (WSSConstants.ATT_NULL_Id.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (WSSConstants.ATT_NULL_AssertionID.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (WSSConstants.ATT_NULL_ID.equals(attributeName) && getAppendAfterThisTokenId().endsWith(attributeValue))) {
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
                if (endElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                    ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).setInSecurityHeader(false);
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
}
