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
