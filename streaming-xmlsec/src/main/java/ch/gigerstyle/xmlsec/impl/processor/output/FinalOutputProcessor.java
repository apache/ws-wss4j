package ch.gigerstyle.xmlsec.impl.processor.output;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.OutputStream;

/**
 * User: giger
 * Date: May 29, 2010
 * Time: 4:25:26 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class FinalOutputProcessor extends AbstractOutputProcessor {

    private XMLEventWriter xmlEventWriter;
    private static final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();

    static {
        xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, true);
    }

    public FinalOutputProcessor(OutputStream outputStream, SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
        try {
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(outputStream, "UTF-8");
        } catch (XMLStreamException e) {
            throw new XMLSecurityException(e);
        }
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        xmlEventWriter.add(xmlEvent);
    }

    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        try {
            xmlEventWriter.flush();
        } catch (XMLStreamException e) {
            throw new XMLSecurityException(e.getMessage(), e);
        }
    }
}
