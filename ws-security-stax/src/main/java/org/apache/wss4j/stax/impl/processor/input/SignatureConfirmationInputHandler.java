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

import org.apache.wss4j.binding.wss11.SignatureConfirmationType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.securityEvent.SignatureConfirmationSecurityEvent;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

import jakarta.xml.bind.JAXBElement;
import java.util.Deque;

/**
 * Processor for the SignatureConfirmation XML Structure
 */
public class SignatureConfirmationInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final SignatureConfirmationType signatureConfirmationType =
                ((JAXBElement<SignatureConfirmationType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        checkBSPCompliance(inputProcessorChain, signatureConfirmationType);

        inputProcessorChain.getSecurityContext().putAsList(SignatureConfirmationType.class, signatureConfirmationType);

        //emit a SignatureConfirmationSecurityEvent
        SignatureConfirmationSecurityEvent signatureConfirmationSecurityEvent = new SignatureConfirmationSecurityEvent();
        signatureConfirmationSecurityEvent.setSignatureValue(signatureConfirmationType.getValue());
        inputProcessorChain.getSecurityContext().registerSecurityEvent(signatureConfirmationSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, SignatureConfirmationType signatureConfirmationType)
        throws WSSecurityException {
        if (signatureConfirmationType.getId() == null) {
            ((WSInboundSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(BSPRule.R5441);
        }
    }
}
