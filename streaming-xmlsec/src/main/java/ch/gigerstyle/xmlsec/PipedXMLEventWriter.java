package ch.gigerstyle.xmlsec;

import javax.xml.namespace.NamespaceContext;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: May 27, 2010
 * Time: 6:57:21 PM
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
public class PipedXMLEventWriter implements XMLEventWriter {
    public void flush() throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void close() throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void add(XMLEvent event) throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void add(XMLEventReader reader) throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public String getPrefix(String uri) throws XMLStreamException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void setPrefix(String prefix, String uri) throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void setDefaultNamespace(String uri) throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void setNamespaceContext(NamespaceContext context) throws XMLStreamException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public NamespaceContext getNamespaceContext() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
