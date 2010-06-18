package ch.gigerstyle.xmlsec;

import javax.xml.stream.XMLStreamException;

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
public interface InputProcessorChain extends ProcessorChain {

    public void addProcessor(InputProcessor inputProcessor);

    public void removeProcessor(InputProcessor inputProcessor);

    public SecurityContext getSecurityContext();

    public InputProcessorChain createSubChain(InputProcessor inputProcessor) throws XMLStreamException, XMLSecurityException;
}
