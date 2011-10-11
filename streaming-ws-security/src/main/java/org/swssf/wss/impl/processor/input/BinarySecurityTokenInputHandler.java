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

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;

import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Processor for the BinarySecurityToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public BinarySecurityTokenInputHandler(final InputProcessorChain inputProcessorChain,
                                           final WSSSecurityProperties securityProperties,
                                           Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        final BinarySecurityTokenType binarySecurityTokenType = (BinarySecurityTokenType) parseStructure(eventQueue, index);

        if (binarySecurityTokenType.getId() == null) {
            binarySecurityTokenType.setId(UUID.randomUUID().toString());
        }

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {
                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }
                securityToken = SecurityTokenFactoryImpl.getSecurityToken(binarySecurityTokenType, inputProcessorChain.getSecurityContext(), crypto, securityProperties.getCallbackHandler(), null);
                securityTokens.put(crypto, securityToken);
                return securityToken;
            }

            public String getId() {
                return binarySecurityTokenType.getId();
            }
        };

        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(binarySecurityTokenType.getId(), securityTokenProvider);

    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new BinarySecurityTokenType(startElement);
    }
}
