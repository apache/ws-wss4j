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
package org.apache.wss4j.policy.model;

import org.apache.neethi.Constants;
import org.apache.neethi.Policy;
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class RequiredElements extends AbstractSecurityAssertion {

    private String xPathVersion;
    private final List<XPath> xPaths = new ArrayList<>();

    public RequiredElements(SPConstants.SPVersion version, String xPathVersion, List<XPath> xPaths) {
        super(version);

        this.xPathVersion = xPathVersion;
        this.xPaths.addAll(xPaths);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getRequiredElements();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new RequiredElements(getVersion(), getXPathVersion(), getXPaths());
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(getName().getPrefix(), getName().getLocalPart(), getName().getNamespaceURI());
        writer.writeNamespace(getName().getPrefix(), getName().getNamespaceURI());
        if (!isNormalized() && isOptional()) {
            writer.writeAttribute(Constants.ATTR_WSP, 
                                  writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), 
                                  Constants.ATTR_OPTIONAL, "true");
        }
        if (getXPathVersion() != null) {
            writer.writeAttribute(SPConstants.XPATH_VERSION, getXPathVersion());
        }
        if (isIgnorable()) {
            writer.writeAttribute(Constants.ATTR_WSP, 
                                  writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), 
                                  Constants.ATTR_IGNORABLE, "true");
        }
        for (int i = 0; i < xPaths.size(); i++) {
            XPath xPath = xPaths.get(i);
            if (XPath.Version.V1 == xPath.getVersion()) {
                writer.writeStartElement(
                        getVersion().getSPConstants().getXPathExpression().getPrefix(),
                        getVersion().getSPConstants().getXPathExpression().getLocalPart(),
                        getVersion().getSPConstants().getXPathExpression().getNamespaceURI());
            } else if (XPath.Version.V2 == xPath.getVersion()) {
                writer.writeStartElement(
                        getVersion().getSPConstants().getXPath2Expression().getPrefix(),
                        getVersion().getSPConstants().getXPath2Expression().getLocalPart(),
                        getVersion().getSPConstants().getXPath2Expression().getNamespaceURI());
                writer.writeNamespace(
                        getVersion().getSPConstants().getXPath2Expression().getPrefix(),
                        getVersion().getSPConstants().getXPath2Expression().getNamespaceURI());
                writer.writeAttribute(SPConstants.FILTER, xPath.getFilter());
            }
            Iterator<Map.Entry<String, String>> namespaceIterator = 
                xPath.getPrefixNamespaceMap().entrySet().iterator();
            while (namespaceIterator.hasNext()) {
                Map.Entry<String, String> namespaceEntry = namespaceIterator.next();
                writer.writeNamespace(namespaceEntry.getKey(), namespaceEntry.getValue());
            }
            writer.writeCharacters(xPath.getXPath());
            writer.writeEndElement();
        }
        writer.writeEndElement();
    }

    public List<XPath> getXPaths() {
        return xPaths;
    }

    public String getXPathVersion() {
        return xPathVersion;
    }

    protected void setXPathVersion(String xPathVersion) {
        this.xPathVersion = xPathVersion;
    }
}
