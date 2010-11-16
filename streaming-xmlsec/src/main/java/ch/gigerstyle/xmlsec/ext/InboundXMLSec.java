package ch.gigerstyle.xmlsec.ext;

import ch.gigerstyle.xmlsec.impl.DocumentContextImpl;
import ch.gigerstyle.xmlsec.impl.InputProcessorChainImpl;
import ch.gigerstyle.xmlsec.impl.XMLEventNSAllocator;
import ch.gigerstyle.xmlsec.impl.XMLSecurityStreamReader;
import ch.gigerstyle.xmlsec.impl.processor.input.LogInputProcessor;
import ch.gigerstyle.xmlsec.impl.processor.input.SecurityHeaderInputProcessor;
import ch.gigerstyle.xmlsec.impl.processor.input.XMLStreamReaderInputProcessor;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEventListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.util.Iterator;
import java.util.List;

/**
 * User: giger
 * Date: Jun 17, 2010
 * Time: 7:49:44 PM
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
public class InboundXMLSec {

    protected static final transient Log log = LogFactory.getLog(InboundXMLSec.class);

    private SecurityProperties securityProperties;

    public InboundXMLSec(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * Warning:
     * configure your xmlStreamReader correctly. Otherwise you can create a security hole.
     * At minimum configure the following properties:
     * xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
     * xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(8192));
     */
    public XMLStreamReader processInMessage(XMLStreamReader xmlStreamReader) throws XMLStreamException, XMLSecurityException {
        return this.processInMessage(xmlStreamReader, null);
    }

    public XMLStreamReader processInMessage(XMLStreamReader xmlStreamReader, SecurityEventListener securityEventListener) throws XMLStreamException, XMLSecurityException {

        final SecurityContextImpl securityContextImpl = new SecurityContextImpl();
        securityContextImpl.setSecurityEventListener(securityEventListener);

        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setEventAllocator(new XMLEventNSAllocator());
        securityContextImpl.put(Constants.XMLINPUTFACTORY, xmlInputFactory);
        final XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(xmlStreamReader);

        DocumentContextImpl documentContext = new DocumentContextImpl();
        documentContext.setEncoding(xmlStreamReader.getEncoding() != null ? xmlStreamReader.getEncoding() : "UTF-8");
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(securityContextImpl, documentContext);
        inputProcessorChain.addProcessor(new XMLStreamReaderInputProcessor(securityProperties, xmlEventReader));
        inputProcessorChain.addProcessor(new SecurityHeaderInputProcessor(securityProperties));

        if (log.isTraceEnabled()) {
            inputProcessorChain.addProcessor(new LogInputProcessor(securityProperties));
        }

        List<InputProcessor> additionalInputProcessors = securityProperties.getInputProcessorList();
        Iterator<InputProcessor> inputProcessorIterator = additionalInputProcessors.iterator();
        while (inputProcessorIterator.hasNext()) {
            InputProcessor inputProcessor = inputProcessorIterator.next();
            inputProcessorChain.addProcessor(inputProcessor);
        }

        return new XMLSecurityStreamReader(inputProcessorChain, securityProperties);
    }
}
