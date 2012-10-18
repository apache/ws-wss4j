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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.binding.wss10.BinarySecurityTokenType;
import org.apache.ws.security.common.bsp.BSPRule;
import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConfigurationException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.impl.securityToken.X509PKIPathv1SecurityToken;
import org.apache.ws.security.stax.impl.securityToken.X509SecurityToken;
import org.apache.ws.security.stax.impl.securityToken.X509_V3SecurityToken;
import org.apache.xml.security.exceptions.XMLSecurityException;
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

    private static final transient Log log = LogFactory.getLog(BinarySecurityTokenInputHandler.class);

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

            private X509SecurityToken binarySecurityToken = null;

            public SecurityToken getSecurityToken() throws XMLSecurityException {
                if (this.binarySecurityToken != null) {
                    return this.binarySecurityToken;
                }
                Crypto crypto = null;
                try {
                    crypto = ((WSSSecurityProperties) securityProperties).getSignatureVerificationCrypto();
                } catch (WSSConfigurationException e) {
                    log.debug(e.getMessage(), e);
                    //ignore
                }
                if (crypto == null) {
                    crypto = ((WSSSecurityProperties) securityProperties).getDecryptionCrypto();
                }

                //only Base64Encoding is supported
                if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badEncoding", binarySecurityTokenType.getEncodingType());
                }

                byte[] securityTokenData = Base64.decodeBase64(binarySecurityTokenType.getValue());

                if (WSSConstants.NS_X509_V3_TYPE.equals(binarySecurityTokenType.getValueType())) {
                    this.binarySecurityToken = new X509_V3SecurityToken(
                            (WSSecurityContext) securityContext, crypto, securityProperties.getCallbackHandler(),
                            securityTokenData, binarySecurityTokenType.getId(), WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE
                    );
                } else if (WSSConstants.NS_X509PKIPathv1.equals(binarySecurityTokenType.getValueType())) {
                    this.binarySecurityToken = new X509PKIPathv1SecurityToken(
                            (WSSecurityContext) securityContext, crypto, securityProperties.getCallbackHandler(),
                            securityTokenData, binarySecurityTokenType.getId(), WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE
                    );
                } else {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "invalidValueType", binarySecurityTokenType.getValueType());
                }

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
        x509TokenSecurityEvent.setSecurityToken((SecurityToken) securityTokenProvider.getSecurityToken());
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
