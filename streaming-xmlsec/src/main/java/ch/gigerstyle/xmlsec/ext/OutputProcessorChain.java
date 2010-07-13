package ch.gigerstyle.xmlsec.ext;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 1:41:10 PM
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
public interface OutputProcessorChain extends ProcessorChain {

    public void processHeaderEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException;

    public SecurityContext getSecurityContext();

    public void addProcessor(OutputProcessor outputProcessor);

    public void removeProcessor(OutputProcessor outputProcessor);

    /**
     * Creates a subchain starts with the outputProcessor + 1
     * Holding a reference to a subchain in a processor and access it in different methods is
     * strictly forbidden. Abusing this rule leads to undefined state (Most probably to a ArrayIndexOutOfBounds exception)  
     * @param outputProcessor
     * @return
     * @throws XMLStreamException
     * @throws XMLSecurityException
     */
    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, XMLSecurityException;
}