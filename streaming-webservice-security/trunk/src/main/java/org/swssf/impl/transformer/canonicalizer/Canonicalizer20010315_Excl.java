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
import org.swssf.ext.ComparableNamespace;
import org.swssf.ext.XMLEventNS;

import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;

public abstract class Canonicalizer20010315_Excl extends CanonicalizerBase {

    public Canonicalizer20010315_Excl(String inclusiveNamespaces, boolean includeComments, OutputStream outputStream) {
        super(inclusiveNamespaces, includeComments, outputStream);
    }

    @Override
    protected void getCurrentUtilizedNamespaces(XMLEventNS xmlEventNS, SortedSet<ComparableNamespace> utilizedNamespaces, C14NStack<List<Comparable>> outputStack) {
        getInitialUtilizedNamespaces(xmlEventNS, utilizedNamespaces, outputStack);
    }

    @Override
    protected void getInitialUtilizedNamespaces(XMLEventNS xmlEventNS, SortedSet<ComparableNamespace> utilizedNamespaces, C14NStack<List<Comparable>> outputStack) {
        List<ComparableNamespace> initialUtilizedNamespace = xmlEventNS.getNamespaceList()[0];
        for (int j = 0; j < initialUtilizedNamespace.size(); j++) {
            ComparableNamespace comparableNamespace = initialUtilizedNamespace.get(j);

            boolean visibleUtilized = false;
            StartElement startElement = xmlEventNS.asStartElement();
            if (comparableNamespace.getPrefix().equals(startElement.getName().getPrefix())) {
                visibleUtilized = true;
            }

            if (!visibleUtilized) {
                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributesIterator = startElement.getAttributes();
                while (attributesIterator.hasNext()) {
                    Attribute attribute = attributesIterator.next();
                    if (comparableNamespace.getPrefix().equals(attribute.getName().getPrefix())) {
                        visibleUtilized = true;
                    }
                }
            }

            if (!visibleUtilized) {
                continue;
            }

            final ComparableNamespace found = (ComparableNamespace) outputStack.containsOnStack(comparableNamespace);
            //found means the prefix matched. so check the ns further
            if (found != null && found.getNamespaceURI() != null && found.getNamespaceURI().equals(comparableNamespace.getNamespaceURI())) {
                continue;
            }

            utilizedNamespaces.add(comparableNamespace);
            outputStack.peek().add(comparableNamespace);
        }
    }

    @Override
    protected void getInitialUtilizedAttributes(XMLEventNS xmlEventNS, SortedSet<ComparableAttribute> utilizedAttributes, C14NStack<List<Comparable>> outputStack) {
        StartElement startElement = xmlEventNS.asStartElement();
        @SuppressWarnings("unchecked")
        Iterator<Attribute> attributesIterator = startElement.getAttributes();
        while (attributesIterator.hasNext()) {
            Attribute attribute = attributesIterator.next();
            utilizedAttributes.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));
        }
    }
}
