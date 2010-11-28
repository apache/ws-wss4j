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

package ch.gigerstyle.xmlsec.policy.secpolicy.model;

import ch.gigerstyle.xmlsec.policy.assertionStates.AssertionState;
import ch.gigerstyle.xmlsec.policy.assertionStates.ContentEncryptedElementAssertionState;
import ch.gigerstyle.xmlsec.policy.secpolicy.SP12Constants;
import ch.gigerstyle.xmlsec.policy.secpolicy.SPConstants;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import org.apache.neethi.PolicyComponent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.*;

public class ContentEncryptedElements extends AbstractSecurityAssertion {

    private ArrayList xPathExpressions = new ArrayList();

    private HashMap declaredNamespaces = new HashMap();

    private String xPathVersion;

    public ContentEncryptedElements(SPConstants spConstants) {
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

        //  <sp:ContentEncryptedElements>
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
                .hasNext();) {
            xpathExpression = (String) iterator.next();
            // <sp:XPath ..>
            writer.writeStartElement(prefix, SPConstants.XPATH_EXPR, namespaceURI);
            writer.writeCharacters(xpathExpression);
            writer.writeEndElement();
        }

        //</sp:ContentEncryptedElements>
        writer.writeEndElement();
    }

    public QName getName() {
        return SP12Constants.CONTENT_ENCRYPTED_ELEMENTS;
    }

    public PolicyComponent normalize() {
        return this;
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        return new SecurityEvent.Event[]{SecurityEvent.Event.ContentEncrypted};
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) {
        Collection<AssertionState> encryptedElementAssertionStates = assertionStateMap.get(SecurityEvent.Event.ContentEncrypted);
        encryptedElementAssertionStates.add(new ContentEncryptedElementAssertionState(this, true, getQNamesFromXPath()));
    }

    private List<QName> getQNamesFromXPath() {
        List<QName> qNames = new ArrayList<QName>(xPathExpressions.size());
        for (int i = 0; i < xPathExpressions.size(); i++) {
            String s = (String) xPathExpressions.get(i);
            String prefix;
            String localName;
            if (s.contains(":")) {
                int idx = s.indexOf(":");
                prefix = s.substring(0, idx);
                localName = s.substring(idx + 1);
            } else {
                prefix = "";
                localName = s;
            }
            qNames.add(new QName((String) declaredNamespaces.get(prefix), localName));
        }
        return qNames;
    }
}
