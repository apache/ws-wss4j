package ch.gigerstyle.xmlsec.impl.processor.output;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * User: giger
 * Date: May 29, 2010
 * Time: 5:24:44 PM
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
public class SecurityHeaderOutputProcessor extends AbstractOutputProcessor {

    public SecurityHeaderOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        outputProcessorChain.processEvent(xmlEvent);

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_soap11_Header)) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security, null);
                subOutputProcessorChain.reset();
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security);
                subOutputProcessorChain.reset();

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
