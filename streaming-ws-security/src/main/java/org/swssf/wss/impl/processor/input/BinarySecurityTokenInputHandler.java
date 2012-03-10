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
package org.swssf.wss.impl.processor.input;

import org.swssf.binding.wss10.BinarySecurityTokenType;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityToken;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.wss.securityEvent.X509TokenSecurityEvent;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;
import java.util.List;
import java.util.UUID;

/**
 * Processor for the BinarySecurityToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        final BinarySecurityTokenType binarySecurityTokenType =
                ((JAXBElement<BinarySecurityTokenType>) parseStructure(eventQueue, index)).getValue();

        if (binarySecurityTokenType.getId() == null) {
            binarySecurityTokenType.setId(UUID.randomUUID().toString());
        }

        final List<QName> elementPath = getElementPath(inputProcessorChain.getDocumentContext(), eventQueue);
        final XMLEvent responsibleStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private WSSecurityToken binarySecurityToken = null;

            public SecurityToken getSecurityToken() throws XMLSecurityException {
                if (this.binarySecurityToken != null) {
                    return this.binarySecurityToken;
                }
                Crypto crypto = null;
                try {
                    crypto = securityProperties.getSignatureVerificationCrypto();
                } catch (XMLSecurityConfigurationException e) {
                    //ignore
                }
                if (crypto == null) {
                    crypto = securityProperties.getDecryptionCrypto();
                }
                this.binarySecurityToken = SecurityTokenFactoryImpl.getSecurityToken(
                        binarySecurityTokenType,
                        inputProcessorChain.getSecurityContext(),
                        crypto,
                        securityProperties.getCallbackHandler());
                this.binarySecurityToken.setElementPath(elementPath);
                this.binarySecurityToken.setXMLEvent(responsibleStartXMLEvent);
                return this.binarySecurityToken;
            }

            public String getId() {
                return binarySecurityTokenType.getId();
            }
        };

        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(binarySecurityTokenType.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(x509TokenSecurityEvent);
    }
}
