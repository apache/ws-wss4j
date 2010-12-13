package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: Nov 9, 2010
 * Time: 7:01:33 PM
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
public class XMLEventReaderInputProcessor extends AbstractInputProcessor {

    private XMLEventReader xmlEventReader;

    public XMLEventReaderInputProcessor(SecurityProperties securityProperties, XMLEventReader xmlEventReader) {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);
        this.xmlEventReader = xmlEventReader;
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = xmlEventReader.nextEvent();
        if (xmlEvent.isStartElement()) {
            inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            inputProcessorChain.getDocumentContext().removePathElement();
        }
        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = xmlEventReader.nextEvent();
        if (xmlEvent.isStartElement()) {
            inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            inputProcessorChain.getDocumentContext().removePathElement();
        }
        return xmlEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //nothing to-do. Also don't call super.doFinal() we are the last processor
    }
}
