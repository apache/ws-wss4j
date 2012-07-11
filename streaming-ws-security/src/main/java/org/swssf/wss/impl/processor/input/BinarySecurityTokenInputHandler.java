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
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.wss.crypto.Crypto;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.util.Deque;
import java.util.List;

/**
 * Processor for the BinarySecurityToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       final Deque<XMLSecEvent> eventQueue, final Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final BinarySecurityTokenType binarySecurityTokenType =
                ((JAXBElement<BinarySecurityTokenType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        checkBSPCompliance(inputProcessorChain, binarySecurityTokenType);

        if (binarySecurityTokenType.getId() == null) {
            binarySecurityTokenType.setId(IDGenerator.generateID(null));
        }

        final List<QName> elementPath = getElementPath(eventQueue);
        final XMLSecEvent responsibleXMLSecStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);
        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();

        final SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private SecurityToken binarySecurityToken = null;

            public SecurityToken getSecurityToken() throws XMLSecurityException {
                if (this.binarySecurityToken != null) {
                    return this.binarySecurityToken;
                }
                Crypto crypto = null;
                try {
                    crypto = ((WSSSecurityProperties)securityProperties).getSignatureVerificationCrypto();
                } catch (XMLSecurityConfigurationException e) {
                    //ignore
                }
                if (crypto == null) {
                    crypto = ((WSSSecurityProperties)securityProperties).getDecryptionCrypto();
                }
                this.binarySecurityToken = SecurityTokenFactoryImpl.getSecurityToken(
                        binarySecurityTokenType,
                        securityContext,
                        crypto,
                        securityProperties.getCallbackHandler());
                this.binarySecurityToken.setElementPath(elementPath);
                this.binarySecurityToken.setXMLSecEvent(responsibleXMLSecStartXMLEvent);
                return this.binarySecurityToken;
            }

            public String getId() {
                return binarySecurityTokenType.getId();
            }
        };

        securityContext.registerSecurityTokenProvider(binarySecurityTokenType.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        securityContext.registerSecurityEvent(x509TokenSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, BinarySecurityTokenType binarySecurityTokenType)
            throws WSSecurityException {
        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (binarySecurityTokenType.getEncodingType() == null) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R3029);
        }
        if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R3030);
        }
        if (binarySecurityTokenType.getValueType() == null) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R3031);
        }
    }
}
