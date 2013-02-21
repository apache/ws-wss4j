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
package org.apache.wss4j.stax.impl.processor.output;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.List;

/**
 * Processor to build the Security Header structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityHeaderOutputProcessor extends AbstractOutputProcessor {

    public SecurityHeaderOutputProcessor() throws XMLSecurityException {
        super();
        setPhase(WSSConstants.Phase.PREPROCESSING);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        boolean eventHandled = false;

        switch (xmlSecEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                final String soapMessageVersion = WSSUtils.getSOAPMessageVersionNamespace(xmlSecStartElement);
                int level = xmlSecStartElement.getDocumentLevel();

                if (level == 1 && soapMessageVersion == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "notASOAPMessage");
                } else if (level == 1) {
                    //set correct namespace on secure parts
                    List<SecurePart> encryptionParts = securityProperties.getEncryptionSecureParts();
                    if (encryptionParts.isEmpty()) {
                        SecurePart securePart = new SecurePart(
                                new QName(soapMessageVersion, WSSConstants.TAG_soap_Body_LocalName),
                                SecurePart.Modifier.Content);
                        outputProcessorChain.getSecurityContext().putAsMap(
                                WSSConstants.ENCRYPTION_PARTS,
                                securePart.getName(), securePart

                        );
                    } else {
                        for (int i = 0; i < encryptionParts.size(); i++) {
                            SecurePart securePart = encryptionParts.get(i);
                            if (securePart.getIdToSign() == null) {
                                outputProcessorChain.getSecurityContext().putAsMap(
                                        WSSConstants.ENCRYPTION_PARTS,
                                        securePart.getName(),
                                        securePart
                                );
                            } else {
                                outputProcessorChain.getSecurityContext().putAsMap(
                                        WSSConstants.ENCRYPTION_PARTS,
                                        securePart.getIdToSign(),
                                        securePart
                                );
                            }
                        }
                    }
                    List<SecurePart> signatureParts = securityProperties.getSignatureSecureParts();
                    if (signatureParts.isEmpty()) {
                        SecurePart securePart = new SecurePart(
                                new QName(soapMessageVersion, WSSConstants.TAG_soap_Body_LocalName),
                                SecurePart.Modifier.Element);
                        outputProcessorChain.getSecurityContext().putAsMap(
                                WSSConstants.SIGNATURE_PARTS,
                                securePart.getName(), securePart
                        );
                    } else {
                        for (int i = 0; i < signatureParts.size(); i++) {
                            SecurePart securePart = signatureParts.get(i);
                            if (securePart.getIdToSign() == null) {
                                outputProcessorChain.getSecurityContext().putAsMap(
                                        WSSConstants.SIGNATURE_PARTS,
                                        securePart.getName(),
                                        securePart
                                );
                            } else {
                                outputProcessorChain.getSecurityContext().putAsMap(
                                        WSSConstants.SIGNATURE_PARTS,
                                        securePart.getIdToSign(),
                                        securePart
                                );
                            }
                        }
                    }
                } else if (level == 3 && WSSConstants.TAG_wsse_Security.equals(xmlSecStartElement.getName())) {
                    if (WSSUtils.isResponsibleActorOrRole(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                        //remove this processor. its no longer needed.
                        outputProcessorChain.removeProcessor(this);
                    }
                } else if (level == 2
                        && WSSConstants.TAG_soap_Body_LocalName.equals(xmlSecStartElement.getName().getLocalPart())
                        && xmlSecStartElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                    //hmm it seems we don't have a soap header in the current document
                    //so output one and add securityHeader

                    //create subchain and output soap-header and securityHeader
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this, xmlSecStartElement.getParentXMLSecStartElement());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain,
                            new QName(soapMessageVersion, WSSConstants.TAG_soap_Header_LocalName, WSSConstants.PREFIX_SOAPENV), true, null);
                    buildSecurityHeader(soapMessageVersion, subOutputProcessorChain);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain,
                            new QName(soapMessageVersion, WSSConstants.TAG_soap_Header_LocalName, WSSConstants.PREFIX_SOAPENV));

                    //output current soap-header event
                    outputProcessorChain.processEvent(xmlSecEvent);
                    //remove this processor. its no longer needed.
                    outputProcessorChain.removeProcessor(this);

                    eventHandled = true;
                }
                break;
            case XMLStreamConstants.END_ELEMENT:
                XMLSecEndElement xmlSecEndElement = xmlSecEvent.asEndElement();
                int documentLevel = xmlSecEndElement.getDocumentLevel();
                if (documentLevel == 2 && WSSConstants.TAG_soap_Header_LocalName.equals(xmlSecEndElement.getName().getLocalPart())
                        && xmlSecEndElement.getName().getNamespaceURI().equals(WSSUtils.getSOAPMessageVersionNamespace(xmlSecEndElement.getParentXMLSecStartElement()))) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    buildSecurityHeader(xmlSecEndElement.getName().getNamespaceURI(), subOutputProcessorChain);
                    //output current soap-header event
                    outputProcessorChain.processEvent(xmlSecEvent);
                    //remove this processor. its no longer needed.
                    outputProcessorChain.removeProcessor(this);

                    eventHandled = true;
                }
                break;
        }

        if (!eventHandled) {
            outputProcessorChain.processEvent(xmlSecEvent);
        }
    }

    private void buildSecurityHeader(String soapMessageVersion, OutputProcessorChain subOutputProcessorChain) throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
        final String actor = ((WSSSecurityProperties) getSecurityProperties()).getActor();
        if (actor != null && !actor.isEmpty()) {
            if (WSSConstants.NS_SOAP11.equals(soapMessageVersion)) {
                attributes.add(createAttribute(WSSConstants.ATT_soap11_Actor, actor));
            } else {
                attributes.add(createAttribute(WSSConstants.ATT_soap12_Role, actor));
            }
        }
        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Security, true, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Security);
    }
}
