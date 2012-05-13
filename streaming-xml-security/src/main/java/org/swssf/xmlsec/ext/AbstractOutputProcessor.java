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

import org.swssf.xmlsec.impl.EncryptionPartDef;
import org.swssf.xmlsec.impl.util.RFC2253Parser;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
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

    protected XMLSecurityProperties securityProperties;
    protected XMLSecurityConstants.Action action;

    private XMLSecurityConstants.Phase phase = XMLSecurityConstants.Phase.PROCESSING;
    private Set<Object> beforeProcessors;
    private Set<Object> afterProcessors;

    protected AbstractOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void setXMLSecurityProperties(XMLSecurityProperties xmlSecurityProperties) {
        this.securityProperties = xmlSecurityProperties;
    }

    @Override
    public void setAction(XMLSecurityConstants.Action action) {
        this.action = action;
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        outputProcessorChain.addProcessor(this);
    }

    public XMLSecurityConstants.Phase getPhase() {
        return phase;
    }

    public void setPhase(XMLSecurityConstants.Phase phase) {
        this.phase = phase;
    }

    public void addBeforeProcessor(Object processor) {
        if (this.beforeProcessors == null) {
            this.beforeProcessors = new HashSet<Object>();
        }
        this.beforeProcessors.add(processor);
    }

    public Set<Object> getBeforeProcessors() {
        if (this.beforeProcessors == null) {
            return Collections.emptySet();
        }
        return this.beforeProcessors;
    }

    public void addAfterProcessor(Object processor) {
        if (this.afterProcessors == null) {
            this.afterProcessors = new HashSet<Object>();
        }
        this.afterProcessors.add(processor);
    }

    public Set<Object> getAfterProcessors() {
        if (this.afterProcessors == null) {
            return Collections.emptySet();
        }
        return this.afterProcessors;
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

        StartElement startElement = xmlEvent.asStartElement();

        List<ComparableNamespace>[] xmlEventNSNamespaces = xmlEventNS.getNamespaceList();
        List<ComparableAttribute>[] xmlEventNsAttributes = xmlEventNS.getAttributeList();

        List<ComparableNamespace> currentXmlEventNamespaces = xmlEventNSNamespaces[0];
        currentXmlEventNamespaces.add(new ComparableNamespace(startElement.getName().getPrefix(), startElement.getName().getNamespaceURI()));

        List<Namespace> namespaceList = new ArrayList<Namespace>();
        @SuppressWarnings("unchecked")
        Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
        while (namespaceIterator.hasNext()) {
            Namespace namespace = namespaceIterator.next();
            namespaceList.add(createNamespace(namespace.getPrefix(), namespace.getNamespaceURI()));
        }

        if (attributeList.size() > 0) {
            Iterator<Attribute> attributeIterator = attributeList.iterator();
            while (attributeIterator.hasNext()) {
                Attribute attribute = attributeIterator.next();
                QName attributeName = attribute.getName();
                String attributeNameNamespaceURI = attributeName.getNamespaceURI();
                if (XMLConstants.NULL_NS_URI.equals(attributeNameNamespaceURI)) {
                    continue;
                }
                boolean found = false;
                String prefix = attributeName.getPrefix();
                for (int j = 0; j < namespaceList.size(); j++) {
                    Namespace namespace = namespaceList.get(j);
                    if (namespace.getPrefix() != null && prefix != null && namespace.getPrefix().equals(prefix)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    namespaceList.add(createNamespace(prefix, attributeNameNamespaceURI));
                    currentXmlEventNamespaces.add(new ComparableNamespace(prefix, attributeNameNamespaceURI));
                }
            }
        }

        startElement = XMLSecurityConstants.XMLEVENTFACTORY.createStartElement(startElement.getName(), attributeList.iterator(), namespaceList.iterator());
        return new XMLEventNS(startElement, xmlEventNSNamespaces, xmlEventNsAttributes);
    }

    protected void createStartElementAndOutputAsEvent(
            OutputProcessorChain outputProcessorChain, QName element, List<Namespace> namespaces, List<Attribute> attributes)
            throws XMLStreamException, XMLSecurityException {

        Iterator<Attribute> attributeListIterator = null;
        if (attributes != null) {
            attributeListIterator = attributes.iterator();
        }
        Iterator<Namespace> namespaceListIterator = null;
        if (namespaces != null) {
            namespaceListIterator = namespaces.iterator();
        }
        StartElement startElement = XMLSecurityConstants.XMLEVENTFACTORY.createStartElement(element, attributeListIterator, namespaceListIterator);
        outputAsEvent(outputProcessorChain, startElement);
    }

    public void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, boolean outputLocalNs,
                                                   List<Attribute> attributes) throws XMLStreamException, XMLSecurityException {

        List<Namespace> namespaceList;
        if (outputLocalNs) {
            namespaceList = new ArrayList<Namespace>(1);
            namespaceList.add(XMLSecurityConstants.XMLEVENTFACTORY.createNamespace(element.getPrefix(), element.getNamespaceURI()));
        } else if (attributes == null) {
            namespaceList = Collections.emptyList();
        } else {
            namespaceList = new ArrayList<Namespace>(1);
        }

        Iterator<Attribute> attributeListIterator = null;
        if (attributes != null) {
            for (int i = 0; i < attributes.size(); i++) {
                Attribute attribute = attributes.get(i);
                QName attributeName = attribute.getName();
                String attributeNamePrefix = attributeName.getPrefix();

                if (attributeNamePrefix != null && attributeNamePrefix.isEmpty()) {
                    continue;
                }

                boolean found = false;
                for (int j = 0; j < namespaceList.size(); j++) {
                    Namespace namespace = namespaceList.get(j);
                    if (namespace.getPrefix() != null && attributeNamePrefix != null && namespace.getPrefix().equals(attributeNamePrefix)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    namespaceList.add(XMLSecurityConstants.XMLEVENTFACTORY.createNamespace(attributeNamePrefix, attributeName.getNamespaceURI()));
                }
            }
            attributeListIterator = attributes.iterator();
        }
        final StartElement startElement = XMLSecurityConstants.XMLEVENTFACTORY.createStartElement(element, attributeListIterator, namespaceList.iterator());
        outputAsEvent(outputProcessorChain, startElement);
    }

    protected EndElement createEndElement(QName element) {
        return XMLSecurityConstants.XMLEVENTFACTORY.createEndElement(element, null);
    }

    public void createEndElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element) throws XMLStreamException, XMLSecurityException {
        outputAsEvent(outputProcessorChain, createEndElement(element));
    }

    public void createCharactersAndOutputAsEvent(OutputProcessorChain outputProcessorChain, String characters) throws XMLStreamException, XMLSecurityException {
        outputAsEvent(outputProcessorChain, createCharacters(characters));
    }

    protected Characters createCharacters(String characters) {
        return XMLSecurityConstants.XMLEVENTFACTORY.createCharacters(characters);
    }

    protected Attribute createAttribute(QName attribute, String attributeValue) {
        return XMLSecurityConstants.XMLEVENTFACTORY.createAttribute(attribute, attributeValue);
    }

    protected Namespace createNamespace(String prefix, String uri) {
        return XMLSecurityConstants.XMLEVENTFACTORY.createNamespace(prefix, uri);
    }

    protected void outputAsEvent(OutputProcessorChain outputProcessorChain, XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlEvent);
    }

    protected void createX509IssuerSerialStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, XMLSecurityException {
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509Data, true, null);
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerSerial, false, null);
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerName, false, null);
        createCharactersAndOutputAsEvent(outputProcessorChain, RFC2253Parser.normalize(x509Certificates[0].getIssuerDN().getName(), true));
        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509IssuerName);
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509SerialNumber, false, null);
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
        List<Attribute> attributes;
        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_ReferenceList, true, null);
        //output the references to the encrypted data:
        Iterator<EncryptionPartDef> encryptionPartDefIterator = encryptionPartDefs.iterator();
        while (encryptionPartDefIterator.hasNext()) {
            EncryptionPartDef encryptionPartDef = encryptionPartDefIterator.next();

            attributes = new ArrayList<Attribute>(1);
            attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_URI, "#" + encryptionPartDef.getEncRefId()));
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_DataReference, false, attributes);
            final String compressionAlgorithm = getSecurityProperties().getEncryptionCompressionAlgorithm();
            if (compressionAlgorithm != null) {
                createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms, true, null);
                attributes = new ArrayList<Attribute>(1);
                attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, compressionAlgorithm));
                createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform, false, attributes);
                createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform);
                createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms);
            }
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
