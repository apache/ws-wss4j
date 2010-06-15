package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.config.Init;
import ch.gigerstyle.xmlsec.processorImpl.*;
import ch.gigerstyle.xmlsec.processorImpl.FinalOutputProcessor;

import javax.xml.stream.*;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Security;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 2:01:16 PM
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
public class XMLSec {

    //todo overall AccessController.doPrivileged

    //todo replace overall "BC" with getProvider somewhere

    static {

        try {
            Class c = XMLSec.class.getClassLoader().loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
            if (null == Security.getProvider("BC")) {
                int i = Security.addProvider((Provider) c.newInstance());
            }
        } catch (Throwable e) {
            throw new RuntimeException("Adding BouncyCastle provider failed", e);
        }
    }

    private SecurityProperties securityProperties;

    public XMLSec(SecurityProperties securityProperties) throws XMLSecurityException {
        Init.init(null);

        if (securityProperties == null) {
            throw new XMLSecurityException("SecurityProperties must not be null!");
        }

        this.securityProperties = securityProperties;
    }

    public XMLStreamReader processInMessage(XMLStreamReader xmlStreamReader) throws XMLStreamException, XMLSecurityException {
        return processInMessage(Constants.xmlInputFactory.createXMLEventReader(xmlStreamReader));
    }

    public XMLStreamReader processInMessage(final XMLEventReader xmlEventReader) throws XMLStreamException, XMLSecurityException {

        final PipedXMLStreamReader pipedXMLStreamReader = new PipedXMLStreamReader(10);
        final PipedOutputInputProcessor pipedOutputProcessor = new PipedOutputInputProcessor(pipedXMLStreamReader, securityProperties);

        Runnable runnable = new Runnable() {

            public void run() {

                try {

                    long start = System.currentTimeMillis();

                    InputProcessorChainImpl processorChain = new InputProcessorChainImpl();

                    //todo dynamic add procs
                    processorChain.addProcessor(new EncryptedKeyInputProcessor(securityProperties));
                    processorChain.addProcessor(new BinarySecurityTokenInputProcessor(securityProperties));
                    processorChain.addProcessor(new SignatureInputProcessor(securityProperties));
                    processorChain.addProcessor(new TimestampInputProcessor(securityProperties));
                    processorChain.addProcessor(new LogInputProcessor(securityProperties));
                    processorChain.addProcessor(pipedOutputProcessor);

                    while (xmlEventReader.hasNext()) {
                        processorChain.processEvent(xmlEventReader.nextEvent());
                        processorChain.reset();
                    }
                    processorChain.reset();
                    processorChain.doFinal();

                    System.out.println("Chain processing time: " + (System.currentTimeMillis() - start));

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        new Thread(runnable).start();

        return pipedXMLStreamReader;
    }

    public XMLStreamWriter processOutMessage(OutputStream outputStream) throws XMLSecurityException {

        OutputProcessorChainImpl processorChain = new OutputProcessorChainImpl();
        //StartSecurityOutputProcessor startSecurityOutputProcessor = new StartSecurityOutputProcessor(securityProperties, finalOutputProcessor);
        //processorChain.addProcessor(startSecurityOutputProcessor);
        processorChain.addProcessor(new SecurityHeaderOutputProcessor(securityProperties));
        processorChain.addProcessor(new TimestampOutputProcessor(securityProperties));
        processorChain.addProcessor(new SignatureOutputProcessor(securityProperties));
        processorChain.addProcessor(new EncryptOutputProcessor(securityProperties));
        processorChain.addProcessor(new FinalOutputProcessor(outputStream, securityProperties));

        return new XMLSecurityStreamWriter(processorChain);
    }
}
