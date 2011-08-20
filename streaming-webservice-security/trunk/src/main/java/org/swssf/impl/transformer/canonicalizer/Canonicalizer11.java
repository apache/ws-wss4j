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
package org.swssf.impl.transformer.canonicalizer;

import org.swssf.ext.ComparableAttribute;
import org.swssf.ext.XMLEventNS;

import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;

public class Canonicalizer11 extends CanonicalizerBase {
    public Canonicalizer11(String inclusiveNamespaces, boolean includeComments, OutputStream outputStream) {
        super(inclusiveNamespaces, includeComments, outputStream);
    }

    @Override
    protected void getInitialUtilizedAttributes(XMLEventNS xmlEventNS, SortedSet<ComparableAttribute> utilizedAttributes, C14NStack<List<Comparable>> outputStack) {
        List<ComparableAttribute>[] visibleAttributeList = xmlEventNS.getAttributeList();
        for (int i = 0; i < visibleAttributeList.length; i++) {
            List<ComparableAttribute> comparableAttributes = visibleAttributeList[i];
            for (int j = 0; j < comparableAttributes.size(); j++) {
                ComparableAttribute comparableAttribute = comparableAttributes.get(j);
                //xml:id attributes must be handled like other attributes: emit but dont inherit
                if (XML.equals(comparableAttribute.getName().getPrefix())
                        && ("id".equals(comparableAttribute.getName().getLocalPart()))
                        || ("base".equals(comparableAttribute.getName().getLocalPart()))) {
                    continue;
                }
                if (outputStack.containsOnStack(comparableAttribute) != null) {
                    continue;
                }
                utilizedAttributes.add(comparableAttribute);
                outputStack.peek().add(comparableAttribute);
            }
        }

        StartElement startElement = xmlEventNS.asStartElement();
        @SuppressWarnings("unchecked")
        Iterator<Attribute> attributesIterator = startElement.getAttributes();
        while (attributesIterator.hasNext()) {
            Attribute attribute = attributesIterator.next();
            //attributes with xml prefix are already processed in the for loop above
            //xml:id attributes must be handled like other attributes: emit but dont inherit
            if (XML.equals(attribute.getName().getPrefix())
                    && !"id".equals(attribute.getName().getLocalPart())
                    && !"base".equals(attribute.getName().getLocalPart())) {
                continue;
            }

            utilizedAttributes.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));
        }
    }
}
