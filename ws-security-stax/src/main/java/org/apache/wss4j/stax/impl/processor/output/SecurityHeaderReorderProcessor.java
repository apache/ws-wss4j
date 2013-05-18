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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.impl.SecurityHeaderOrder;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.output.FinalOutputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.*;

/**
 * The basic ordering (token dependencies) is given through the processor order
 * but we have more ordering criterias e.g. signed timestamp and strict header ordering ws-policy.
 * To be able to sign a timestamp the processor must be inserted before the signature processor but that
 * means that the timestamp is below the signature in the sec-header. Because of the highly dynamic nature
 * of the processor chain (and encryption makes it far more worse) we have to order the headers afterwards.
 * So that is what this processor does, the final header reordering...
 */
public class SecurityHeaderReorderProcessor extends AbstractOutputProcessor {

    final private Map<XMLSecurityConstants.Action, Map<QName, Deque<XMLSecEvent>>> actionEventMap =
            new LinkedHashMap<XMLSecurityConstants.Action, Map<QName, Deque<XMLSecEvent>>>();

    private int securityHeaderIndex = 0;
    private Deque<XMLSecEvent> currentDeque;

    public SecurityHeaderReorderProcessor() throws XMLSecurityException {
        super();
        setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        addBeforeProcessor(FinalOutputProcessor.class.getName());
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);

        XMLSecurityConstants.Action[] outActions = getSecurityProperties().getOutAction();
        for (int i = outActions.length - 1; i >= 0; i--) {
            XMLSecurityConstants.Action outAction = outActions[i];
            actionEventMap.put(outAction, new TreeMap<QName, Deque<XMLSecEvent>>(new Comparator<QName>() {
                @Override
                public int compare(QName o1, QName o2) {
                    if (WSSConstants.TAG_dsig_Signature.equals(o1)) {
                        return 1;
                    } else if (WSSConstants.TAG_dsig_Signature.equals(o2)) {
                        return -1;
                    }
                    return 1;
                }
            }));
        }
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        int documentLevel = xmlSecEvent.getDocumentLevel();
        if (documentLevel < 3 ||
                !WSSUtils.isInSecurityHeader(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
            outputProcessorChain.processEvent(xmlSecEvent);
            return;
        }

        //now we are in our security header

        if (documentLevel == 3) {
            if (xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(WSSConstants.TAG_wsse_Security)) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                Iterator<Map.Entry<XMLSecurityConstants.Action, Map<QName, Deque<XMLSecEvent>>>> iterator = actionEventMap.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<XMLSecurityConstants.Action, Map<QName, Deque<XMLSecEvent>>> next = iterator.next();
                    Iterator<Map.Entry<QName, Deque<XMLSecEvent>>> entryIterator = next.getValue().entrySet().iterator();
                    while (entryIterator.hasNext()) {
                        Map.Entry<QName, Deque<XMLSecEvent>> entry = entryIterator.next();
                        Deque<XMLSecEvent> xmlSecEvents = entry.getValue();
                        while (!xmlSecEvents.isEmpty()) {
                            XMLSecEvent event = xmlSecEvents.pop();
                            subOutputProcessorChain.reset();
                            subOutputProcessorChain.processEvent(event);
                        }
                    }
                }
                outputProcessorChain.removeProcessor(this);
            }
            outputProcessorChain.processEvent(xmlSecEvent);
            return;
        } else if (documentLevel == 4) {
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

                    List<SecurityHeaderOrder> securityHeaderOrderList = outputProcessorChain.getSecurityContext().getAsList(SecurityHeaderOrder.class);
                    SecurityHeaderOrder securityHeaderOrder = securityHeaderOrderList.get(securityHeaderIndex);
                    if (!xmlSecStartElement.getName().equals(WSSConstants.TAG_xenc_EncryptedData) &&
                            !xmlSecStartElement.getName().equals(securityHeaderOrder.getSecurityHeaderElementName())) {
                        throw new WSSecurityException(
                                WSSecurityException.ErrorCode.FAILURE, "empty",
                                "Invalid security header order. Expected " +
                                        securityHeaderOrder.getSecurityHeaderElementName() +
                                        " but got " + xmlSecStartElement.getName());
                    }

                    Map<QName, Deque<XMLSecEvent>> map = null;
                    if (!securityHeaderOrder.isEncrypted()) {
                        map = actionEventMap.get(securityHeaderOrder.getAction());
                    } else {
                        Iterator<Map.Entry<XMLSecurityConstants.Action, Map<QName, Deque<XMLSecEvent>>>> iterator = actionEventMap.entrySet().iterator();
                        while (iterator.hasNext()) {
                            Map.Entry<XMLSecurityConstants.Action, Map<QName, Deque<XMLSecEvent>>> next = iterator.next();
                            if (next.getKey().getName().contains("Encrypt")) {
                                map = next.getValue();
                                break;
                            }
                        }
                        if (map == null) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", "No encrypt action found");
                        }
                    }
                    currentDeque = new ArrayDeque<XMLSecEvent>();
                    map.put(securityHeaderOrder.getSecurityHeaderElementName(), currentDeque);

                    securityHeaderIndex++;
                    break;
            }
        }
        currentDeque.offer(xmlSecEvent);
    }
}
