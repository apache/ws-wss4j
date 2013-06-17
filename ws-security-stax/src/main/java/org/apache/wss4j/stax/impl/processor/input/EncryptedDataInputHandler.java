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
package org.apache.wss4j.stax.impl.processor.input;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.xml.security.binding.xmlenc.ReferenceList;
import org.apache.xml.security.binding.xmlenc.ReferenceType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.stream.events.Attribute;
import java.util.Deque;
import java.util.Iterator;

/**
 * Processor for the EncryptedData XML Structure in the security header
 */
public class EncryptedDataInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       final Deque<XMLSecEvent> eventQueue, final Integer index) throws XMLSecurityException {

        XMLSecEvent xmlSecEvent = null;
        final Iterator<XMLSecEvent> xmlSecEventIterator = eventQueue.descendingIterator();
        int curIdx = 0;
        while (curIdx++ <= index) {
            xmlSecEvent = xmlSecEventIterator.next();
        }
        if (!(xmlSecEvent instanceof XMLSecStartElement)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
        }
        final XMLSecStartElement encryptedDataElement = xmlSecEvent.asStartElement();
        final Attribute idAttribute = encryptedDataElement.getAttributeByName(XMLSecurityConstants.ATT_NULL_Id);

        DecryptInputProcessor decryptInputProcessor =
                new DecryptInputProcessor(null, new ReferenceList(), (WSSSecurityProperties) securityProperties,
                        (WSInboundSecurityContext) inputProcessorChain.getSecurityContext()) {

                    @Override
                    protected ReferenceType matchesReferenceId(XMLSecStartElement xmlSecStartElement) {
                        if (xmlSecStartElement == encryptedDataElement) {
                            ReferenceType referenceType = new ReferenceType();
                            if (idAttribute != null) {
                                final String uri = idAttribute.getValue();
                                referenceType.setURI("#" + uri);
                                inputProcessorChain.getSecurityContext().putAsList(WSSConstants.PROP_ENCRYPTED_DATA_REFS, uri);
                            }
                            inputProcessorChain.removeProcessor(this);
                            return referenceType;
                        }
                        return null;
                    }
                };
        inputProcessorChain.addProcessor(decryptInputProcessor);
    }
}
