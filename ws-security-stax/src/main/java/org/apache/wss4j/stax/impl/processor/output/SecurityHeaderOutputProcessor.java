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
                            // Check to see if the wrong SOAP NS was used
                            SecurePart convertedPart = convertSecurePart(securePart, soapMessageVersion);
                            if (securePart != convertedPart) {
                                securePart = convertedPart;
                                encryptionParts.set(i, securePart);
                            }
                            
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
                            // Check to see if the wrong SOAP NS was used
                            SecurePart convertedPart = convertSecurePart(securePart, soapMessageVersion);
                            if (securePart != convertedPart) {
                                securePart = convertedPart;
                                signatureParts.set(i, securePart);
                            }
                            
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
                } else if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                        //remove this processor. its no longer needed.
                        outputProcessorChain.removeProcessor(this);                    
                } else if (level == 2
                        && WSSConstants.TAG_soap_Body_LocalName.equals(xmlSecStartElement.getName().getLocalPart())
                        && xmlSecStartElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                    //hmm it seems we don't have a soap header in the current document
                    //so output one and add securityHeader

                    //create subchain and output soap-header and securityHeader
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this, xmlSecStartElement.getParentXMLSecStartElement());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain,
                            new QName(soapMessageVersion, WSSConstants.TAG_soap_Header_LocalName, WSSConstants.PREFIX_SOAPENV), true, null);
                    boolean mustUnderstand = ((WSSSecurityProperties) getSecurityProperties()).isMustUnderstand();
                    buildSecurityHeader(soapMessageVersion, subOutputProcessorChain, mustUnderstand);
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
                    boolean mustUnderstand = ((WSSSecurityProperties) getSecurityProperties()).isMustUnderstand();
                    buildSecurityHeader(xmlSecEndElement.getName().getNamespaceURI(), subOutputProcessorChain, mustUnderstand);
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
    
    private SecurePart convertSecurePart(SecurePart securePart, String soapVersion) {
        final QName secureName = securePart.getName();
        if (secureName == null) {
            return securePart;
        }

        QName newName = secureName;
        
        if (WSSConstants.NS_SOAP11.equals(secureName.getNamespaceURI())
            && WSSConstants.NS_SOAP12.equals(soapVersion)) {
            newName = new QName(soapVersion, secureName.getLocalPart(), secureName.getPrefix());
        } else if (WSSConstants.NS_SOAP12.equals(secureName.getNamespaceURI())
            && WSSConstants.NS_SOAP11.equals(soapVersion)) {
            newName = new QName(soapVersion, secureName.getLocalPart(), secureName.getPrefix());
        }
        
        if (!secureName.equals(newName)) {
            SecurePart newPart = 
                new SecurePart(newName, securePart.isGenerateXPointer(), securePart.getModifier(),
                               securePart.getTransforms(), securePart.getDigestMethod());
            newPart.setExternalReference(securePart.getExternalReference());
            newPart.setIdToReference(securePart.getIdToReference());
            newPart.setIdToSign(securePart.getIdToSign());
            return newPart;
        }
        
        return securePart;
    }

    private void buildSecurityHeader(
        String soapMessageVersion, 
        OutputProcessorChain subOutputProcessorChain,
        boolean mustUnderstand
    ) throws XMLStreamException, XMLSecurityException {
        List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
        final String actor = ((WSSSecurityProperties) getSecurityProperties()).getActor();
        if (actor != null && !actor.isEmpty()) {
            if (WSSConstants.NS_SOAP11.equals(soapMessageVersion)) {
                attributes.add(createAttribute(WSSConstants.ATT_soap11_Actor, actor));
            } else {
                attributes.add(createAttribute(WSSConstants.ATT_soap12_Role, actor));
            }
        }
        if (mustUnderstand) {
            if (WSSConstants.NS_SOAP11.equals(soapMessageVersion)) {
                attributes.add(createAttribute(WSSConstants.ATT_soap11_MustUnderstand, "1"));
            } else {
                attributes.add(createAttribute(WSSConstants.ATT_soap12_MustUnderstand, "true"));
            }
        }
        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Security, true, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Security);
    }
}
