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

import org.apache.xml.security.binding.xmlenc.ReferenceList;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

import java.util.Deque;

/**
 * Processor for the ReferenceList XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class ReferenceListInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       final Deque<XMLSecEvent> eventQueue, final Integer index) throws XMLSecurityException {

        final ReferenceList referenceList = (ReferenceList) parseStructure(eventQueue, index, securityProperties);

        //instantiate a new DecryptInputProcessor and add it to the chain
        inputProcessorChain.addProcessor(
                new DecryptInputProcessor(null, referenceList, (WSSSecurityProperties) securityProperties,
                        (WSSecurityContext) inputProcessorChain.getSecurityContext()));
    }
}
