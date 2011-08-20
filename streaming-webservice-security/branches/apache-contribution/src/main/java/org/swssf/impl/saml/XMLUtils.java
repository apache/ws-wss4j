package org.swssf.impl.saml;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * User: giger
 * Date: 5/2/11
 * Time: 10:24 PM
 * Copyright 2011 Marc Giger gigerstyle@gmx.ch
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
public class XMLUtils {

    /**
     * Gets a direct child with specified localname and namespace. <p/>
     *
     * @param parentNode the node where to start the search
     * @param localName  local name of the child to get
     * @param namespace  the namespace of the child to get
     * @return the node or <code>null</code> if not such node found
     */
    public static Element getDirectChildElement(Node parentNode, String localName, String namespace) {
        if (parentNode == null) {
            return null;
        }
        for (
                Node currentChild = parentNode.getFirstChild();
                currentChild != null;
                currentChild = currentChild.getNextSibling()
                ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                    && localName.equals(currentChild.getLocalName())
                    && namespace.equals(currentChild.getNamespaceURI())) {
                return (Element) currentChild;
            }
        }
        return null;
    }
}
