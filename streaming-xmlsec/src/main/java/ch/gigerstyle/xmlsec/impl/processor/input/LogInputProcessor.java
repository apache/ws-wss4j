package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.StringWriter;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 12:24:56 PM
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
public class LogInputProcessor extends AbstractInputProcessor {

    public LogInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
        this.getBeforeProcessors().add(PipedInputProcessor.class.getName());
    }

    @Override
    public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        //System.out.println("Event: " + xmlEvent);
        StringWriter stringWriter = new StringWriter();
        xmlEvent.writeAsEncodedUnicode(stringWriter);
        System.out.print(stringWriter.toString());
        inputProcessorChain.processEvent(xmlEvent);
    }
}
