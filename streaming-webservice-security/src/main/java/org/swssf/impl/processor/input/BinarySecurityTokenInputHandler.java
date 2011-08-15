/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.input;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.SecurityTokenFactory;

import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;

/**
 * Processor for the BinarySecurityToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public BinarySecurityTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final BinarySecurityTokenType binarySecurityTokenType = (BinarySecurityTokenType) parseStructure(eventQueue, index);

        if (binarySecurityTokenType.getId() != null) {

            SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                    return SecurityTokenFactory.newInstance().getSecurityToken(binarySecurityTokenType, crypto, securityProperties.getCallbackHandler(), null);
                }

                public String getId() {
                    return binarySecurityTokenType.getId();
                }
            };

            inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(binarySecurityTokenType.getId(), securityTokenProvider);
        }
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new BinarySecurityTokenType(startElement);
    }
}
