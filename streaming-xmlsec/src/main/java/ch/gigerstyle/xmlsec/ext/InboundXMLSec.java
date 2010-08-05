package ch.gigerstyle.xmlsec.ext;

import ch.gigerstyle.xmlsec.impl.InputProcessorChainImpl;
import ch.gigerstyle.xmlsec.impl.processor.input.LogInputProcessor;
import ch.gigerstyle.xmlsec.impl.processor.input.PipedInputProcessor;
import ch.gigerstyle.xmlsec.impl.processor.input.PipedXMLStreamReader;
import ch.gigerstyle.xmlsec.impl.processor.input.SecurityHeaderInputProcessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

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

    public XMLStreamReader processInMessage(XMLStreamReader xmlStreamReader) throws XMLStreamException, XMLSecurityException {
        return processInMessage(Constants.xmlInputFactory.createXMLEventReader(xmlStreamReader));
    }

    //todo this method should not be public we need our own xmlEventReader and not a foreign one... (XMLEventNS)

    public XMLStreamReader processInMessage(final XMLEventReader xmlEventReader) throws XMLStreamException, XMLSecurityException {

        final PipedXMLStreamReader pipedXMLStreamReader = new PipedXMLStreamReader(10);
        final PipedInputProcessor pipedInputProcessor = new PipedInputProcessor(pipedXMLStreamReader, securityProperties);

        Runnable runnable = new Runnable() {

            public void run() {

                try {

                    pipedXMLStreamReader.setWriteSide(Thread.currentThread());

                    long start = System.currentTimeMillis();

                    InputProcessorChainImpl processorChain = new InputProcessorChainImpl();

                    processorChain.addProcessor(new SecurityHeaderInputProcessor(securityProperties, processorChain));
                    //todo dynamic add procs
                    /*processorChain.addProcessor(new EncryptedKeyInputProcessor(securityProperties));
                    processorChain.addProcessor(new ReferenceListInputProcessor(securityProperties));
                    processorChain.addProcessor(new BinarySecurityTokenInputProcessor(securityProperties));
                    processorChain.addProcessor(new SignatureInputProcessor(securityProperties));
                    processorChain.addProcessor(new TimestampInputProcessor(securityProperties));
                    */
                    processorChain.addProcessor(pipedInputProcessor);

                    if (log.isTraceEnabled()) {
                        processorChain.addProcessor(new LogInputProcessor(securityProperties));
                    }

                    while (xmlEventReader.hasNext()) {
                        processorChain.processEvent(xmlEventReader.nextEvent());
                        processorChain.reset();
                    }
                    processorChain.doFinal();

                    log.debug("Chain processing time: " + (System.currentTimeMillis() - start));

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        new Thread(runnable).start();

        return pipedXMLStreamReader;
    }
}
