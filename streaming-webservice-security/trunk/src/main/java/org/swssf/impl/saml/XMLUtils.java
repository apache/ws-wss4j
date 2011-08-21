/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.saml;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author $Author$
 * @version $Revision$ $Date$
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
