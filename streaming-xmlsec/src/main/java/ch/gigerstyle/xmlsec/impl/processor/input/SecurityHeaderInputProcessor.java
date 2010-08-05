package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.util.FiFoQueue;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeaderType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * User: giger
 * Date: Jun 23, 2010
 * Time: 9:32:17 PM
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
public class SecurityHeaderInputProcessor extends AbstractInputProcessor {

    private int level = 0;
    private boolean isInSecurityHeader = false;
    private FiFoQueue<XMLEvent> xmlEventList = new FiFoQueue<XMLEvent>();
    private InternalSecurityHeaderProcessor internalSecurityHeaderProcessor;

    public SecurityHeaderInputProcessor(SecurityProperties securityProperties, InputProcessorChain inputProcessorChain) {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);

        internalSecurityHeaderProcessor = new InternalSecurityHeaderProcessor(securityProperties);
        inputProcessorChain.addProcessor(internalSecurityHeaderProcessor);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {
                isInSecurityHeader = true;
            }
            if (isInSecurityHeader) {
                level++;
            }

            if (level == 2) {
                if (startElement.getName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
                    inputProcessorChain.addProcessor(new BinarySecurityTokenInputProcessor(getSecurityProperties()));
                } else if (startElement.getName().equals(Constants.TAG_xenc_EncryptedKey)) {
                    inputProcessorChain.addProcessor(new EncryptedKeyInputProcessor(getSecurityProperties()));
                } else if (startElement.getName().equals(Constants.TAG_dsig_Signature)) {
                    inputProcessorChain.addProcessor(new SignatureInputProcessor(getSecurityProperties()));
                } else if (startElement.getName().equals(Constants.TAG_wsu_Timestamp)) {
                    inputProcessorChain.addProcessor(new TimestampInputProcessor(getSecurityProperties()));
                } else if (startElement.getName().equals(Constants.TAG_xenc_ReferenceList)) {
                    inputProcessorChain.addProcessor(new ReferenceListInputProcessor(getSecurityProperties()));
                }
            }
        }
            
        inputProcessorChain.processSecurityHeaderEvent(xmlEvent);

        if (xmlEvent.isEndElement()) {
            if (isInSecurityHeader) {
                level--;
            }
            EndElement endElement = xmlEvent.asEndElement();
            if (endElement.getName().equals(Constants.TAG_wsse_Security) && level == 0) {
                isInSecurityHeader = false;

                inputProcessorChain.removeProcessor(internalSecurityHeaderProcessor);

                InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);                
                //replay all events in "normal" processing chain
                while (!xmlEventList.isEmpty()) {
                    XMLEvent event = xmlEventList.dequeue();
                    subInputProcessorChain.reset();
                    subInputProcessorChain.processEvent(event);
                }
        
                //remove this processor from chain now. the next events will go directly to the other processors
                inputProcessorChain.removeProcessor(this);
            }
        }
    }

    class InternalSecurityHeaderProcessor extends AbstractInputProcessor {

        InternalSecurityHeaderProcessor(SecurityProperties securityProperties) {
            super(securityProperties);
            setPhase(Constants.Phase.POSTPROCESSING);
            getBeforeProcessors().add(PipedInputProcessor.class.getName());
        }

        @Override
        public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
            xmlEventList.enqueue(xmlEvent);
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
            //should never be called because we remove this processor before
            inputProcessorChain.processEvent(xmlEvent);
        }
    }
}
