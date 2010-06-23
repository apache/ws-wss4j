package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

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
    
    public SecurityHeaderInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {

            StartElement startElement = xmlEvent.asStartElement();

            if (isInSecurityHeader && level == 1) {
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

            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {
                isInSecurityHeader = true;
            }
            if (isInSecurityHeader) {
                level++;
            }
        }
        else if (xmlEvent.isEndElement()) {
            if (isInSecurityHeader) {
                level--;
            }
            EndElement endElement = xmlEvent.asEndElement();
            if (endElement.getName().equals(Constants.TAG_wsse_Security)) {
                isInSecurityHeader = false;
                //this works only if we have just one Security header...
                inputProcessorChain.removeProcessor(this);
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
