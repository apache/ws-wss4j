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
package org.apache.ws.security.stax.impl.processor.output;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.output.AbstractEncryptEndingOutputProcessor;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.*;

/**
 * Processor buffers encrypted XMLEvents and forwards them when final is called
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptEndingOutputProcessor extends AbstractEncryptEndingOutputProcessor {

    private static final List<QName> appendAfterOneOfThisAttributes;

    static {
        List<QName> list = new ArrayList<QName>(5);
        list.add(WSSConstants.ATT_wsu_Id);
        list.add(WSSConstants.ATT_NULL_Id);
        list.add(WSSConstants.ATT_NULL_AssertionID);
        list.add(WSSConstants.ATT_NULL_ID);
        appendAfterOneOfThisAttributes = Collections.unmodifiableList(list);
    }

    public EncryptEndingOutputProcessor() throws XMLSecurityException {
        super();
        this.addAfterProcessor(EncryptOutputProcessor.class.getName());
        this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
    }

    @Override
    public void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
        if (getAction() == WSSConstants.ENCRYPT_WITH_DERIVED_KEY) {
            WSSUtils.createReferenceListStructureForEncryption(this, subOutputProcessorChain);
        }
    }

    @Override
    protected List<QName> getAppendAfterOneOfThisAttributes() {
        return appendAfterOneOfThisAttributes;
    }

    @Override
    public void flushBufferAndCallbackAfterTokenID(OutputProcessorChain outputProcessorChain,
                                                   Deque<XMLSecEvent> xmlSecEventDeque)
            throws XMLStreamException, XMLSecurityException {

        final String actor = ((WSSSecurityProperties) getSecurityProperties()).getActor();

        //loop until we reach our security header
        loop:
        while (!xmlSecEventDeque.isEmpty()) {
            XMLSecEvent xmlSecEvent = xmlSecEventDeque.pop();
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                    if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                            && WSSUtils.isResponsibleActorOrRole(
                            xmlSecStartElement, actor)) {
                        outputProcessorChain.reset();
                        outputProcessorChain.processEvent(xmlSecEvent);
                        break loop;
                    }
                    break;
            }
            outputProcessorChain.reset();
            outputProcessorChain.processEvent(xmlSecEvent);
        }
        super.flushBufferAndCallbackAfterTokenID(outputProcessorChain, xmlSecEventDeque);
    }
}
