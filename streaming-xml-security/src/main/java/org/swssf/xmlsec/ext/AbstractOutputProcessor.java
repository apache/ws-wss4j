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
package org.swssf.xmlsec.ext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.xmlsec.impl.EncryptionPartDef;
import org.swssf.xmlsec.impl.util.RFC2253Parser;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * An abstract OutputProcessor class for reusabilty
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractOutputProcessor implements OutputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected static final XMLEventFactory xmlEventFactory = XMLEventFactory.newInstance();
    protected XMLSecurityProperties securityProperties;
    protected XMLSecurityConstants.Action action;

    private XMLSecurityConstants.Phase phase = XMLSecurityConstants.Phase.PROCESSING;
    private Set<Object> beforeProcessors = new HashSet<Object>();
    private Set<Object> afterProcessors = new HashSet<Object>();

    protected AbstractOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        this.securityProperties = securityProperties;
        this.action = action;
    }

    public XMLSecurityConstants.Phase getPhase() {
        return phase;
    }

    public void setPhase(XMLSecurityConstants.Phase phase) {
        this.phase = phase;
    }

    public Set<Object> getBeforeProcessors() {
        return beforeProcessors;
    }

    public Set<Object> getAfterProcessors() {
        return afterProcessors;
    }

    public XMLSecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public XMLSecurityConstants.Action getAction() {
        return action;
    }

    public abstract void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;

    public void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        processEvent(xmlEvent, outputProcessorChain);
    }

    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.doFinal();
    }

    //todo copy attributes
    protected XMLEventNS cloneStartElementEvent(XMLEvent xmlEvent, List<Attribute> attributeList) throws XMLStreamException {
        XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;
        if (!xmlEvent.isStartElement()) {
            return xmlEventNS;
        }

        List<ComparableNamespace>[] xmlEventNSNamespaces = xmlEventNS.getNamespaceList();
        List<ComparableAttribute>[] xmlEventNsAttributes = xmlEventNS.getAttributeList();

        List<ComparableNamespace> currentXmlEventNamespaces = xmlEventNSNamespaces[0];
        currentXmlEventNamespaces.add(new ComparableNamespace(xmlEvent.asStartElement().getName().getPrefix(), xmlEvent.asStartElement().getName().getNamespaceURI()));

        List<Namespace> namespaceList = new ArrayList<Namespace>();
        @SuppressWarnings("unchecked")
        Iterator<Namespace> namespaceIterator = xmlEvent.asStartElement().getNamespaces();
        while (namespaceIterator.hasNext()) {
            Namespace namespace = namespaceIterator.next();
            namespaceList.add(createNamespace(namespace.getPrefix(), namespace.getNamespaceURI()));
        }

        for (int i = 0; i < attributeList.size(); i++) {
            Attribute attribute = attributeList.get(i);
            boolean found = false;
            for (int j = 0; j < namespaceList.size(); j++) {
                Namespace namespace = namespaceList.get(j);
                if (namespace.getPrefix() != null && attribute.getName().getPrefix() != null && namespace.getPrefix().equals(attribute.getName().getPrefix())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                namespaceList.add(createNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
                currentXmlEventNamespaces.add(new ComparableNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
            }
        }

        StartElement startElement = xmlEventFactory.createStartElement(xmlEvent.asStartElement().getName(), attributeList.iterator(), namespaceList.iterator());

        return new XMLEventNS(startElement, xmlEventNSNamespaces, xmlEventNsAttributes);
    }

    protected void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, Map<QName, String> namespaces, Map<QName, String> attributes) throws XMLStreamException, XMLSecurityException {
        List<Attribute> attributeList = new LinkedList<Attribute>();
        if (attributes != null) {
            Iterator<Map.Entry<QName, String>> attributeIterator = attributes.entrySet().iterator();
            while (attributeIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = attributeIterator.next();
                Attribute attribute = xmlEventFactory.createAttribute(qNameStringEntry.getKey(), qNameStringEntry.getValue());
                attributeList.add(attribute);
            }
        }
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        if (namespaces != null) {
            Iterator<Map.Entry<QName, String>> namespaceIterator = namespaces.entrySet().iterator();
            while (namespaceIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = namespaceIterator.next();
                namespaceList.add(xmlEventFactory.createNamespace(qNameStringEntry.getKey().getLocalPart(), qNameStringEntry.getValue()));
            }
        }
        StartElement startElement = xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator());
        outputAsEvent(outputProcessorChain, startElement);
    }

    public void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, Map<QName, String> attributes) throws XMLStreamException, XMLSecurityException {
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        namespaceList.add(xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));

        List<Attribute> attributeList = new LinkedList<Attribute>();
        if (attributes != null) {
            Iterator<Map.Entry<QName, String>> attributeIterator = attributes.entrySet().iterator();
            while (attributeIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = attributeIterator.next();
                Attribute attribute = xmlEventFactory.createAttribute(qNameStringEntry.getKey(), qNameStringEntry.getValue());
                attributeList.add(attribute);

                if ("".equals(attribute.getName().getPrefix())) {
                    continue;
                }

                boolean found = false;
                for (int i = 0; i < namespaceList.size(); i++) {
                    Namespace namespace = namespaceList.get(i);
                    if (namespace.getPrefix() != null && attribute.getName().getPrefix() != null && namespace.getPrefix().equals(attribute.getName().getPrefix())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    namespaceList.add(xmlEventFactory.createNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
                }
            }
        }

        StartElement startElement = xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator());
        outputAsEvent(outputProcessorChain, startElement);
    }

    protected EndElement createEndElement(QName element) {
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        namespaceList.add(xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));
        return xmlEventFactory.createEndElement(element, namespaceList.iterator());
    }

    public void createEndElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element) throws XMLStreamException, XMLSecurityException {
        outputAsEvent(outputProcessorChain, createEndElement(element));
    }

    public void createCharactersAndOutputAsEvent(OutputProcessorChain outputProcessorChain, String characters) throws XMLStreamException, XMLSecurityException {
        outputAsEvent(outputProcessorChain, createCharacters(characters));
    }

    protected Characters createCharacters(String characters) {
        return xmlEventFactory.createCharacters(characters);
    }

    protected Attribute createAttribute(QName attribute, String attributeValue) {
        return xmlEventFactory.createAttribute(attribute, attributeValue);
    }

    protected Namespace createNamespace(String prefix, String uri) {
        return xmlEventFactory.createNamespace(prefix, uri);
    }

    protected void outputAsEvent(OutputProcessorChain outputProcessorChain, XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlEvent);
    }

    protected void createX509IssuerSerialStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, XMLSecurityException {
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509Data, null);
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerSerial, null);
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerName, null);
        createCharactersAndOutputAsEvent(outputProcessorChain, RFC2253Parser.normalize(x509Certificates[0].getIssuerDN().getName(), true));
        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerName);
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509SerialNumber, null);
        createCharactersAndOutputAsEvent(outputProcessorChain, x509Certificates[0].getSerialNumber().toString());
        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509SerialNumber);
        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerSerial);
        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509Data);
    }

    protected void createReferenceListStructure(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        List<EncryptionPartDef> encryptionPartDefs = outputProcessorChain.getSecurityContext().getAsList(EncryptionPartDef.class);
        if (encryptionPartDefs == null) {
            return;
        }
        Map<QName, String> attributes;
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_ReferenceList, null);
        //output the references to the encrypted data:
        Iterator<EncryptionPartDef> encryptionPartDefIterator = encryptionPartDefs.iterator();
        while (encryptionPartDefIterator.hasNext()) {
            EncryptionPartDef encryptionPartDef = encryptionPartDefIterator.next();

            attributes = new HashMap<QName, String>();
            attributes.put(XMLSecurityConstants.ATT_NULL_URI, "#" + encryptionPartDef.getEncRefId());
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_DataReference, attributes);
            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_DataReference);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_ReferenceList);
    }

    protected SecurePart securePartMatches(StartElement startElement, OutputProcessorChain outputProcessorChain, List<SecurePart> secureParts) {
        SecurePart securePart = securePartMatches(startElement, secureParts);
        if (securePart != null) {
            return securePart;
        }
        List<SecurePart> dynamicSecureParts = outputProcessorChain.getSecurityContext().getAsList(SecurePart.class);
        if (dynamicSecureParts == null) {
            return null;
        }
        return securePartMatches(startElement, dynamicSecureParts);
    }

    protected SecurePart securePartMatches(StartElement startElement, List<SecurePart> secureParts) {
        Iterator<SecurePart> securePartIterator = secureParts.iterator();
        while (securePartIterator.hasNext()) {
            SecurePart securePart = securePartIterator.next();
            if (securePart.getIdToSign() == null) {
                if (startElement.getName().getLocalPart().equals(securePart.getName())
                        && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {
                    return securePart;
                }
            } else {
                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributeIterator = startElement.getAttributes();
                while (attributeIterator.hasNext()) {
                    Attribute attribute = attributeIterator.next();
                    if (attribute != null) {
                        QName attributeName = attribute.getName();
                        if ((attributeName.equals(XMLSecurityConstants.ATT_NULL_Id))
                                && attribute.getValue().equals(securePart.getIdToSign())) {
                            return securePart;
                        }
                    }
                }
            }
        }
        return null;
    }
}
