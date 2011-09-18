/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
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

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
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
