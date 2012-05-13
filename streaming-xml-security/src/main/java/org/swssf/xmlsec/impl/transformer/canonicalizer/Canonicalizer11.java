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
package org.swssf.xmlsec.impl.transformer.canonicalizer;

import org.swssf.xmlsec.ext.ComparableAttribute;
import org.swssf.xmlsec.ext.XMLEventNS;

import javax.xml.namespace.QName;
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
public class Canonicalizer11 extends CanonicalizerBase {
    public Canonicalizer11(List<String> inclusiveNamespaces, boolean includeComments, OutputStream outputStream) {
        super(inclusiveNamespaces, includeComments, outputStream);
    }

    @Override
    protected void getInitialUtilizedAttributes(final XMLEventNS xmlEventNS, final SortedSet<ComparableAttribute> utilizedAttributes,
                                                final C14NStack<List<Comparable>> outputStack) {

        final List<ComparableAttribute>[] visibleAttributeList = xmlEventNS.getAttributeList();
        for (int i = 0; i < visibleAttributeList.length; i++) {
            final List<ComparableAttribute> comparableAttributes = visibleAttributeList[i];
            for (int j = 0; j < comparableAttributes.size(); j++) {
                final ComparableAttribute comparableAttribute = comparableAttributes.get(j);
                //xml:id attributes must be handled like other attributes: emit but dont inherit
                final QName comparableAttributeName = comparableAttribute.getName();
                if (XML.equals(comparableAttributeName.getPrefix())
                        && ("id".equals(comparableAttributeName.getLocalPart()))
                        || ("base".equals(comparableAttributeName.getLocalPart()))) {
                    continue;
                }
                if (outputStack.containsOnStack(comparableAttribute) != null) {
                    continue;
                }
                utilizedAttributes.add(comparableAttribute);
                outputStack.peek().add(comparableAttribute);
            }
        }

        final StartElement startElement = xmlEventNS.asStartElement();
        @SuppressWarnings("unchecked")
        final Iterator<Attribute> attributesIterator = startElement.getAttributes();
        while (attributesIterator.hasNext()) {
            final Attribute attribute = attributesIterator.next();
            //attributes with xml prefix are already processed in the for loop above
            //xml:id attributes must be handled like other attributes: emit but dont inherit
            final QName attributeName = attribute.getName();
            if (XML.equals(attributeName.getPrefix())
                    && !"id".equals(attributeName.getLocalPart())
                    && !"base".equals(attributeName.getLocalPart())) {
                continue;
            }

            utilizedAttributes.add(new ComparableAttribute(attributeName, attribute.getValue()));
        }
    }
}
