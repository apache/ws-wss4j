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
package org.apache.ws.security.stax.impl.processor.input;

import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.securityEvent.OperationSecurityEvent;
import org.apache.xml.security.stax.ext.AbstractInputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.List;

/**
 * Processor which emits the Operation-Security-Event
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class OperationInputProcessor extends AbstractInputProcessor {

    public OperationInputProcessor(XMLSecurityProperties securityProperties) {
        super(securityProperties);
        this.setPhase(WSSConstants.Phase.POSTPROCESSING);
        this.addBeforeProcessor(SecurityHeaderInputProcessor.class.getName());
    }

    @Override
    public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        return inputProcessorChain.processHeaderEvent();
    }

    @Override
    public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        XMLSecEvent xmlSecEvent = inputProcessorChain.processEvent();
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
            List<QName> elementPath = xmlSecStartElement.getElementPath();
            if (elementPath.size() == 3 && WSSUtils.isInSOAPBody(elementPath)) {
                OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
                operationSecurityEvent.setOperation(xmlSecEvent.asStartElement().getName());
                operationSecurityEvent.setCorrelationID(IDGenerator.generateID(null));
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(operationSecurityEvent);
                inputProcessorChain.removeProcessor(this);
            }
        }
        return xmlSecEvent;
    }
}
