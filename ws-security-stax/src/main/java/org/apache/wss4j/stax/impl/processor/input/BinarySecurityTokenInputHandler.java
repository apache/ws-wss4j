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
import java.util.List;

import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.wss4j.binding.wss10.BinarySecurityTokenType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.KerberosTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.KerberosServiceSecurityToken;
import org.apache.wss4j.stax.securityToken.X509SecurityToken;
import org.apache.wss4j.stax.validate.BinarySecurityTokenValidator;
import org.apache.wss4j.stax.validate.BinarySecurityTokenValidatorImpl;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

/**
 * Processor for the BinarySecurityToken XML Structure
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

        final WSInboundSecurityContext wsInboundSecurityContext =
            (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;
        final List<QName> elementPath = getElementPath(eventQueue);
        final List<XMLSecEvent> xmlSecEvents = getResponsibleXMLSecEvents(eventQueue, index);

        final TokenContext tokenContext =
            new TokenContext(wssSecurityProperties, wsInboundSecurityContext, xmlSecEvents, elementPath);

        BinarySecurityTokenValidator binarySecurityTokenValidator =
                wssSecurityProperties.getValidator(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);
        if (binarySecurityTokenValidator == null) {
            binarySecurityTokenValidator = new BinarySecurityTokenValidatorImpl();
        }
        final InboundSecurityToken binarySecurityToken =
                binarySecurityTokenValidator.validate(binarySecurityTokenType, tokenContext);

        SecurityTokenProvider<InboundSecurityToken> securityTokenProvider = new SecurityTokenProvider<InboundSecurityToken>() {
            @Override
            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {
                return binarySecurityToken;
            }

            @Override
            public String getId() {
                return binarySecurityToken.getId();
            }
        };

        wsInboundSecurityContext.registerSecurityTokenProvider(binarySecurityTokenType.getId(), securityTokenProvider);

        TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent;
        //fire a tokenSecurityEvent
        if (binarySecurityTokenType.getValueType().startsWith(WSSConstants.NS_X509TOKEN_PROFILE)) {
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            x509TokenSecurityEvent.setSecurityToken((X509SecurityToken) binarySecurityToken);
            tokenSecurityEvent = x509TokenSecurityEvent;
        } else if (binarySecurityTokenType.getValueType().startsWith(WSSConstants.NS_KERBEROS11_TOKEN_PROFILE)) {
            KerberosTokenSecurityEvent kerberosTokenSecurityEvent = new KerberosTokenSecurityEvent();
            kerberosTokenSecurityEvent.setSecurityToken((KerberosServiceSecurityToken)binarySecurityToken);
            tokenSecurityEvent = kerberosTokenSecurityEvent;
        } else {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "invalidValueType",
                    new Object[] {binarySecurityTokenType.getValueType()});
        }
        tokenSecurityEvent.setCorrelationID(binarySecurityTokenType.getId());
        wsInboundSecurityContext.registerSecurityEvent(tokenSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, BinarySecurityTokenType binarySecurityTokenType)
            throws WSSecurityException {

        final WSInboundSecurityContext securityContext = (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
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
