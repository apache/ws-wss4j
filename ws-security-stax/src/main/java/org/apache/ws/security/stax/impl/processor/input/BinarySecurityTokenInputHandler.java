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

import java.util.Deque;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.binding.wss10.BinarySecurityTokenType;
import org.apache.ws.security.common.bsp.BSPRule;
import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.impl.securityToken.SecurityTokenFactoryImpl;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.SecurityTokenProvider;
import org.apache.xml.security.stax.ext.XMLSecurityConfigurationException;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;

/**
 * Processor for the BinarySecurityToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenInputHandler extends AbstractInputSecurityHeaderHandler {
    
    private static final transient Log log = 
            LogFactory.getLog(BinarySecurityTokenInputHandler.class);

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
                    log.debug(e.getMessage(), e);
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
        x509TokenSecurityEvent.setCorrelationID(binarySecurityTokenType.getId());
        securityContext.registerSecurityEvent(x509TokenSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, BinarySecurityTokenType binarySecurityTokenType)
            throws WSSecurityException {
        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (binarySecurityTokenType.getEncodingType() == null) {
            securityContext.handleBSPRule(BSPRule.R3029);
        }
        if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
            securityContext.handleBSPRule(BSPRule.R3030);
        }
        if (binarySecurityTokenType.getValueType() == null) {
            securityContext.handleBSPRule(BSPRule.R3031);
        }
    }
}
