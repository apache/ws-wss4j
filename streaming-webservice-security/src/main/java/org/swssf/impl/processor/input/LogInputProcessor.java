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

import org.swssf.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.StringWriter;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class LogInputProcessor extends AbstractInputProcessor {

    public LogInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
        this.getAfterProcessors().add(SecurityHeaderInputProcessor.class.getName());
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return inputProcessorChain.processHeaderEvent();
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processEvent();
        StringWriter stringWriter = new StringWriter();
        xmlEvent.writeAsEncodedUnicode(stringWriter);
        logger.trace(stringWriter.toString());
        return xmlEvent;
    }
}
