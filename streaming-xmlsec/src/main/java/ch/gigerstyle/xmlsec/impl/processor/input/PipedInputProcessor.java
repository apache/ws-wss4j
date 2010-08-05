package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.IOException;

/**
 * User: giger
 * Date: May 27, 2010
 * Time: 7:11:25 PM
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
public class PipedInputProcessor extends AbstractInputProcessor {

    private PipedXMLStreamReader sink;

    public PipedInputProcessor(PipedXMLStreamReader pipedXMLStreamReader, SecurityProperties securityProperties) throws XMLStreamException {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
        getAfterProcessors().add(SecurityHeaderInputProcessor.InternalSecurityHeaderProcessor.class.getName());
        connect(pipedXMLStreamReader);
    }

    /**
     * Connects this piped output stream to a receiver. If this object
     * is already connected to some other piped input stream, an
     * <code>XMLStreamException</code> is thrown.
     * <p/>
     * If <code>snk</code> is an unconnected piped input stream and
     * <code>src</code> is an unconnected piped output stream, they may
     * be connected by either the call:
     * <blockquote><pre>
     * src.connect(snk)</pre></blockquote>
     * or the call:
     * <blockquote><pre>
     * snk.connect(src)</pre></blockquote>
     * The two calls have the same effect.
     *
     * @param snk the piped input stream to connect to.
     * @throws XMLStreamException if an I/O error occurs.
     */
    public synchronized void connect(PipedXMLStreamReader snk) throws XMLStreamException {
        if (snk == null) {
            throw new NullPointerException();
        } else if (sink != null || snk.connected) {
            throw new XMLStreamException("Already connected");
        }
        sink = snk;
        snk.in = -1;
        snk.out = 0;
        snk.connected = true;
    }

    @Override
    public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (sink == null) {
            throw new XMLStreamException("Pipe not connected");
        }
        try {
            sink.receive(((XMLEventNS) xmlEvent).getCurrentEvent());
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (sink != null) {
            sink.receivedLast();
        }
    }
}
