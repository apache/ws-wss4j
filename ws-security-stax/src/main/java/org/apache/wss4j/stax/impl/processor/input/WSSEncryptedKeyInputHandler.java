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
package org.apache.wss4j.stax.impl.processor.input;

import org.apache.wss4j.binding.wss10.ObjectFactory;
import org.apache.wss4j.binding.wss10.ReferenceType;
import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmlenc.EncryptedKeyType;
import org.apache.xml.security.binding.xmlenc.EncryptionMethodType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.processor.input.XMLEncryptedKeyInputHandler;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;

/**
 * Processor for the EncryptedKey XML Structure
 */
public class WSSEncryptedKeyInputHandler extends XMLEncryptedKeyInputHandler {

    private static final transient org.slf4j.Logger log =
        org.slf4j.LoggerFactory.getLogger(WSSEncryptedKeyInputHandler.class);

    @Override
    public void handle(InputProcessorChain inputProcessorChain, EncryptedKeyType encryptedKeyType, XMLSecEvent responsibleXMLSecStartXMLEvent, XMLSecurityProperties securityProperties) throws XMLSecurityException {
        checkBSPCompliance(inputProcessorChain, encryptedKeyType);

        // Check encryption algorithm against the required algorithm, if defined
        EncryptionMethodType encryptionMethodType = encryptedKeyType.getEncryptionMethod();
        if (securityProperties.getEncryptionKeyTransportAlgorithm() != null
            && encryptionMethodType != null) {
            String encryptionMethod = encryptionMethodType.getAlgorithm();
            if (!securityProperties.getEncryptionKeyTransportAlgorithm().equals(encryptionMethod)) {
                log.debug(
                    "The Key transport method does not match the requirement"
                );
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
            }
        }

        super.handle(inputProcessorChain, encryptedKeyType, responsibleXMLSecStartXMLEvent, securityProperties);
    }

    //if this EncryptedKey structure contains a reference list, instantiate a new DecryptInputProcessor
    //and add it to the chain
    @Override
    protected void handleReferenceList(final InputProcessorChain inputProcessorChain,
            final EncryptedKeyType encryptedKeyType,
            final XMLSecurityProperties securityProperties) throws XMLSecurityException {
        KeyInfoType keyInfoType = new KeyInfoType();
        SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
        ReferenceType referenceType = new ReferenceType();
        referenceType.setURI("#" + encryptedKeyType.getId());
        ObjectFactory objectFactory = new ObjectFactory();
        securityTokenReferenceType.getAny().add(objectFactory.createReference(referenceType));
        keyInfoType.getContent().add(objectFactory.createSecurityTokenReference(securityTokenReferenceType));
        inputProcessorChain.addProcessor(
                new DecryptInputProcessor(keyInfoType, encryptedKeyType.getReferenceList(),
                        (WSSSecurityProperties) securityProperties,
                        (WSInboundSecurityContext) inputProcessorChain.getSecurityContext())
                );
    }

    protected void checkBSPCompliance(InputProcessorChain inputProcessorChain, EncryptedKeyType encryptedKeyType)
            throws XMLSecurityException {
        final WSInboundSecurityContext securityContext = (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
        if (encryptedKeyType.getType() != null) {
            securityContext.handleBSPRule(BSPRule.R3209);
        }
        if (encryptedKeyType.getMimeType() != null) {
            securityContext.handleBSPRule(BSPRule.R5622);
        }
        if (encryptedKeyType.getEncoding() != null) {
            securityContext.handleBSPRule(BSPRule.R5623);
        }
        if (encryptedKeyType.getRecipient() != null) {
            securityContext.handleBSPRule(BSPRule.R5602);
        }
        EncryptionMethodType encryptionMethodType = encryptedKeyType.getEncryptionMethod();
        if (encryptionMethodType == null) {
            securityContext.handleBSPRule(BSPRule.R5603);
        } else {
            String encryptionMethod = encryptionMethodType.getAlgorithm();
            if (!(WSSConstants.NS_XENC_RSA15.equals(encryptionMethod)
                || WSSConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionMethod)
                || WSSConstants.NS_XENC11_RSAOAEP.equals(encryptionMethod))) {
                securityContext.handleBSPRule(BSPRule.R5621);
            }
        }
    }

    /*
    <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncKeyId-1483925398">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                <wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
                    ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier">pHoiKNGY2YsLBKxwIV+jURt858M=</wsse:KeyIdentifier>
                </wsse:SecurityTokenReference>
        </ds:KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue>Khsa9SN3ALNXOgGDKOqihvfwGsXb9QN/q4Fpi9uuThgz+3D4oRSMkrGSPCqwG13vddvHywGAA/XNbWNT+5Xivz3lURCDCc2H/92YlXXo/crQNJnPlLrLZ81bGOzbNo7lnYQBLp/77K7b1bhldZAeV9ZfEW7DjbOMZ+k1dnDCu3A=</xenc:CipherValue>
        </xenc:CipherData>
        <xenc:ReferenceList>
            <xenc:DataReference URI="#EncDataId-1612925417" />
        </xenc:ReferenceList>
    </xenc:EncryptedKey>
     */
}
