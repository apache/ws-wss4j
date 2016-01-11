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

import java.util.Deque;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.xml.security.binding.xmlenc.ReferenceList;
import org.apache.xml.security.binding.xmlenc.ReferenceType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputProcessor;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Processor for the EncryptedData XML Structure in the security header.
 * Note, this handler is special in respect to when it is called: it is triggered by the
 * EncryptedData StartElement and not when the EndElement occurs. @see comments in SecurityHeaderInputProcessort
 */
public class EncryptedDataInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       final Deque<XMLSecEvent> eventQueue, final Integer index) throws XMLSecurityException {

        XMLSecEvent xmlSecEvent = eventQueue.pollFirst();
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
                            return referenceType;
                        }
                        return null;
                    }
                };
        inputProcessorChain.addProcessor(decryptInputProcessor);

        //replay the EncryptedData event for the DecryptInputProcessor:
        InputProcessor tmpProcessor = new AbstractInputProcessor(securityProperties) {
            @Override
            public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) 
                throws XMLStreamException, XMLSecurityException {
                inputProcessorChain.removeProcessor(this);
                return encryptedDataElement;
            }

            @Override
            public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain) 
                throws XMLStreamException, XMLSecurityException {
                inputProcessorChain.removeProcessor(this);
                return encryptedDataElement;
            }
        };
        tmpProcessor.addBeforeProcessor(decryptInputProcessor);
        inputProcessorChain.addProcessor(tmpProcessor);
    }
}
