package ch.gigerstyle.xmlsec.processorImpl;

import ch.gigerstyle.xmlsec.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: May 31, 2010
 * Time: 6:17:55 PM
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
public class StartSecurityOutputProcessor extends AbstractOutputProcessor {

    FinalOutputProcessor finalOutputProcessor;

    public StartSecurityOutputProcessor(SecurityProperties securityProperties, FinalOutputProcessor finalOutputProcessor) throws XMLSecurityException {
        super(securityProperties);
        this.finalOutputProcessor = finalOutputProcessor;
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        super.doFinal(outputProcessorChain, securityContext);
    }
}
