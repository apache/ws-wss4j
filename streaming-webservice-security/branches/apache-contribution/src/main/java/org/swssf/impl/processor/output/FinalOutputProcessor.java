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
package org.swssf.impl.processor.output;

import org.swssf.ext.*;

import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.OutputStream;

/**
 * Processor which outputs the XMLEvents to an outputStream
 * This Processor can be extended to allow to write to a StAX writer instead of directly to an output stream
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class FinalOutputProcessor extends AbstractOutputProcessor {

    private XMLEventWriter xmlEventWriter;
    private static final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();

    static {
        xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, false);
    }

    public FinalOutputProcessor(OutputStream outputStream, String encoding, SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
        setPhase(Constants.Phase.POSTPROCESSING);
        try {
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(outputStream, encoding);
        } catch (XMLStreamException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        xmlEventWriter.add(xmlEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws WSSecurityException {
        try {
            xmlEventWriter.flush();
            xmlEventWriter.close();
        } catch (XMLStreamException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }
}
