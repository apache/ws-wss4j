/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.swssf.policy.secpolicy.model;

import org.apache.neethi.PolicyComponent;
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.*;

/**
 * class lent from apache rampart
 */
public class RequiredElements extends AbstractSecurityAssertion {

    private ArrayList xPathExpressions = new ArrayList();

    private HashMap declaredNamespaces = new HashMap();

    private String xPathVersion;

    public RequiredElements(SPConstants spConstants) {
        setVersion(spConstants);
    }

    /**
     * @return Returns the xPathExpressions.
     */
    public ArrayList getXPathExpressions() {
        return xPathExpressions;
    }

    public void addXPathExpression(String expr) {
        this.xPathExpressions.add(expr);
    }

    /**
     * @return Returns the xPathVersion.
     */
    public String getXPathVersion() {
        return xPathVersion;
    }

    /**
     * @param pathVersion The xPathVersion to set.
     */
    public void setXPathVersion(String pathVersion) {
        xPathVersion = pathVersion;
    }

    public HashMap getDeclaredNamespaces() {
        return declaredNamespaces;
    }

    public void addDeclaredNamespaces(String uri, String prefix) {
        declaredNamespaces.put(prefix, uri);
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {

        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix;
        String writerPrefix = writer.getPrefix(namespaceURI);

        if (writerPrefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        } else {
            prefix = writerPrefix;
        }

        //  <sp:RequiredElements>
        writer.writeStartElement(prefix, localName, namespaceURI);

        // xmlns:sp=".."
        writer.writeNamespace(prefix, namespaceURI);

        if (writerPrefix == null) {
            // xmlns:sp=".."
            writer.writeNamespace(prefix, namespaceURI);
        }

        if (xPathVersion != null) {
            writer.writeAttribute(prefix, namespaceURI, SPConstants.XPATH_VERSION, xPathVersion);
        }

        String xpathExpression;

        for (Iterator iterator = xPathExpressions.iterator(); iterator
                .hasNext(); ) {
            xpathExpression = (String) iterator.next();
            // <sp:XPath ..>
            writer.writeStartElement(prefix, SPConstants.XPATH_EXPR, namespaceURI);
            writer.writeCharacters(xpathExpression);
            writer.writeEndElement();
        }

        //</sp:RequiredElements>
        writer.writeEndElement();
    }

    public QName getName() {
        return spConstants.getRequiredElements();
    }

    public PolicyComponent normalize() {
        return this;
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        //todo
        return new SecurityEvent.Event[0];
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap, OperationPolicy operationPolicy) {
        //todo
    }

    /*
    @Override
    public void assertPolicy(SecurityEvent securityEvent) throws PolicyViolationException {
    }

    @Override
    public boolean isAsserted() {
        return true;
    }
    */
}
