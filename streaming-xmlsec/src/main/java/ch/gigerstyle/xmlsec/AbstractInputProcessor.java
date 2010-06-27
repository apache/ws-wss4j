package ch.gigerstyle.xmlsec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 1:32:12 PM
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
public abstract class AbstractInputProcessor implements InputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    private SecurityProperties securityProperties;
    private QName lastStartElementName = new QName("", "");

    public AbstractInputProcessor(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    public abstract void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException;

    public void processNextEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            lastStartElementName = xmlEvent.asStartElement().getName();
        }
        processEvent(xmlEvent, inputProcessorChain, securityContext);
    }

    public void doFinal(InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        inputProcessorChain.doFinal();
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public QName getLastStartElementName() {
        return lastStartElementName;
    }
}
