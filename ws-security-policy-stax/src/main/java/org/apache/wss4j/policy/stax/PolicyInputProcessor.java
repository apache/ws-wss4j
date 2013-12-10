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
package org.apache.wss4j.policy.stax;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.impl.processor.input.SecurityHeaderInputProcessor;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.RequiredElementSecurityEvent;
import org.apache.wss4j.stax.securityEvent.RequiredPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import java.util.List;

/**
 * Processor to generate SecurityEvents regarding not secured elements
 */
public class PolicyInputProcessor extends AbstractInputProcessor {

    private final PolicyEnforcer policyEnforcer;
    private boolean initDone = false;
    private boolean transportSecurityActive = false;

    public PolicyInputProcessor(PolicyEnforcer policyEnforcer, XMLSecurityProperties securityProperties) {
        super(securityProperties);
        this.setPhase(WSSConstants.Phase.POSTPROCESSING);
        this.addBeforeProcessor(SecurityHeaderInputProcessor.class.getName());
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLSecEvent xmlSecEvent = inputProcessorChain.processHeaderEvent();
        //test if non encrypted element have to be encrypted per policy
        init(inputProcessorChain);
        //if transport security is active, every element is encrypted/signed
        //WSP1.3, 4.2.1 EncryptedParts Assertion
        List<QName> elementPath = null;
        if (!transportSecurityActive) {
            elementPath = xmlSecEvent.getElementPath();
            if (!inputProcessorChain.getDocumentContext().isInEncryptedContent()
                    && WSSUtils.isInSecurityHeader(xmlSecEvent, elementPath,
                    ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                testEncryptionPolicy(xmlSecEvent, elementPath);
            }
        }
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
            if (elementPath == null) {
                elementPath = xmlSecStartElement.getElementPath();
            }
            final int documentLevel = elementPath.size();
            if (documentLevel == 3 && WSSUtils.isInSOAPHeader(elementPath)) {

                RequiredPartSecurityEvent requiredPartSecurityEvent = new RequiredPartSecurityEvent();
                requiredPartSecurityEvent.setElementPath(elementPath);
                policyEnforcer.registerSecurityEvent(requiredPartSecurityEvent);
                RequiredElementSecurityEvent requiredElementSecurityEvent = new RequiredElementSecurityEvent();
                requiredElementSecurityEvent.setElementPath(elementPath);
                policyEnforcer.registerSecurityEvent(requiredElementSecurityEvent);
            } else if (documentLevel > 3) {
                //test for required elements
                RequiredElementSecurityEvent requiredElementSecurityEvent = new RequiredElementSecurityEvent();
                requiredElementSecurityEvent.setElementPath(elementPath);
                policyEnforcer.registerSecurityEvent(requiredElementSecurityEvent);
            }
        }
        return xmlSecEvent;
    }

    @Override
    public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLSecEvent xmlSecEvent = inputProcessorChain.processEvent();

        List<QName> elementPath = null;
        switch (xmlSecEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                int documentLevel = xmlSecStartElement.getDocumentLevel();
                //test for required elements
                if (documentLevel > 3) {
                    RequiredElementSecurityEvent requiredElementSecurityEvent = new RequiredElementSecurityEvent();
                    elementPath = xmlSecStartElement.getElementPath();
                    requiredElementSecurityEvent.setElementPath(elementPath);
                    policyEnforcer.registerSecurityEvent(requiredElementSecurityEvent);
                }
                break;
        }

        //if transport security is active, every element is encrypted/signed
        //WSP1.3, 4.2.1 EncryptedParts Assertion
        //test if non encrypted element have to be encrypted per policy
        if (!transportSecurityActive) {
            final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
            final boolean inEncryptedContent = documentContext.isInEncryptedContent();
            final boolean inSignedContent = documentContext.isInSignedContent();
            if (!inEncryptedContent || !inSignedContent) {
                if (elementPath == null) {
                    elementPath = xmlSecEvent.getElementPath();
                }
                if (!inEncryptedContent
                        && !WSSUtils.isInSecurityHeader(xmlSecEvent, elementPath,
                        ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    testEncryptionPolicy(xmlSecEvent, elementPath);
                }

                //WSP1.3, 4.1.1 SignedParts Assertion
                //test if non signed element have to be signed per policy
                if (!inSignedContent) {
                    testSignaturePolicy(xmlSecEvent, elementPath);
                }
            }
        }
        return xmlSecEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        super.doFinal(inputProcessorChain);

        try {
            policyEnforcer.doFinal();
        } catch (WSSPolicyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }

    private void testSignaturePolicy(XMLSecEvent xmlSecEvent, List<QName> elementPath) throws WSSecurityException {
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            final int documentLevel = elementPath.size();
            if (documentLevel == 3 && WSSUtils.isInSOAPHeader(elementPath)) {
                SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, false, null);
                signedPartSecurityEvent.setElementPath(elementPath);
                policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
            } else if (documentLevel == 2 && WSSUtils.isInSOAPBody(elementPath)) {
                SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, false, null);
                signedPartSecurityEvent.setElementPath(elementPath);
                policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
            } else if (documentLevel > 3) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(null, false, null);
                signedElementSecurityEvent.setElementPath(elementPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }
    }

    private void testEncryptionPolicy(XMLSecEvent xmlSecEvent, List<QName> elementPath) throws WSSecurityException {
        //the following events are only interesting for policy verification. So call directly the policyEnforcer for these
        switch (xmlSecEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                final int documentLevel = elementPath.size();
                if (documentLevel == 3 && WSSUtils.isInSOAPHeader(elementPath)) {

                    EncryptedPartSecurityEvent encryptedPartSecurityEvent
                            = new EncryptedPartSecurityEvent(null, false, null);
                    encryptedPartSecurityEvent.setElementPath(elementPath);
                    policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
                }
                //the body element has documentLevel 2 but we have to use 3 because
                //the body element itself is never encrypted but child elements are. So we
                //test for the body child element.
                else if (documentLevel == 3 && WSSUtils.isInSOAPBody(elementPath)) {

                    EncryptedPartSecurityEvent encryptedPartSecurityEvent
                            = new EncryptedPartSecurityEvent(null, false, null);
                    encryptedPartSecurityEvent.setElementPath(elementPath);
                    policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
                } else if (documentLevel > 3) {

                    EncryptedElementSecurityEvent encryptedElementSecurityEvent
                            = new EncryptedElementSecurityEvent(null, false, null);
                    encryptedElementSecurityEvent.setCorrelationID(getId(xmlSecEvent));
                    encryptedElementSecurityEvent.setElementPath(elementPath);
                    policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

                    //... or it could be a contentEncryption too...
                    ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent
                            = new ContentEncryptedElementSecurityEvent(null, false, null);
                    contentEncryptedElementSecurityEvent.setElementPath(xmlSecEvent.getParentXMLSecStartElement().getElementPath());
                    policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);
                }
                break;
            case XMLStreamConstants.CHARACTERS:
            case XMLStreamConstants.ENTITY_REFERENCE:
            case XMLStreamConstants.PROCESSING_INSTRUCTION:
                //can only be a content encryption
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent
                        = new ContentEncryptedElementSecurityEvent(null, false, null);
                contentEncryptedElementSecurityEvent.setElementPath(xmlSecEvent.getElementPath());
                policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);
                break;
        }
    }
    
    protected String getId(XMLSecEvent xmlSecEvent) {
        XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
        if (xmlSecStartElement.getOnElementDeclaredAttributes().size() >= 0) {
            Attribute attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_wsu_Id);
            if (attribute != null) {
                return attribute.getValue();
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_Id);
            if (attribute != null) {
                return attribute.getValue();
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_ID);
            if (attribute != null) {
                return attribute.getValue();
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_AssertionID);
            if (attribute != null) {
                return attribute.getValue();
            }
        }
        return null;
    }

    protected void init(InputProcessorChain inputProcessorChain) {
        if (!this.initDone) {
            this.initDone = true;
            this.transportSecurityActive = Boolean.TRUE == inputProcessorChain.getSecurityContext().get(WSSConstants.TRANSPORT_SECURITY_ACTIVE);
            inputProcessorChain.getSecurityContext().put(WSSConstants.PROP_ALLOW_RSA15_KEYTRANSPORT_ALGORITHM, Boolean.TRUE);
            inputProcessorChain.getSecurityContext().put(WSSConstants.PROP_ALLOW_USERNAMETOKEN_NOPASSWORD, Boolean.TRUE.toString());
        }
    }
}
