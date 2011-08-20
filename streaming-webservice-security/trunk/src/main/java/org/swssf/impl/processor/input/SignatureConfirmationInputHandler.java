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

import org.oasis_open.docs.wss.oasis_wss_wssecurity_secext_1_1.SignatureConfirmationType;
import org.swssf.ext.*;

import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;

/**
 * Processor for the SignatureConfirmation XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureConfirmationInputHandler extends AbstractInputSecurityHeaderHandler {

    public SignatureConfirmationInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final SignatureConfirmationType signatureConfirmationType = (SignatureConfirmationType) parseStructure(eventQueue, index);
        inputProcessorChain.getSecurityContext().putAsList(SignatureConfirmationType.class, signatureConfirmationType);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SignatureConfirmationType(startElement);
    }
}
