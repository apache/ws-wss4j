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
package org.swssf.wss.impl.processor.input;

import org.swssf.binding.wss10.SecurityTokenReferenceType;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmlenc.EncryptedDataType;
import org.apache.xml.security.binding.xmlenc.ReferenceList;
import org.apache.xml.security.binding.xmlenc.ReferenceType;
import org.swssf.wss.ext.*;
import org.swssf.wss.securityEvent.ContentEncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.EncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.EncryptedPartSecurityEvent;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.input.AbstractDecryptInputProcessor;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * Processor for decryption of EncryptedData XML structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DecryptInputProcessor extends AbstractDecryptInputProcessor {

    public DecryptInputProcessor(KeyInfoType keyInfoType, ReferenceList referenceList,
                                 WSSSecurityProperties securityProperties, WSSecurityContext securityContext)
            throws XMLSecurityException {

        super(keyInfoType, referenceList, securityProperties);
        checkBSPCompliance(keyInfoType, referenceList, securityContext, WSSConstants.BSPRule.R3006);
    }

    private void checkBSPCompliance(KeyInfoType keyInfoType, ReferenceList referenceList, WSSecurityContext securityContext,
                                    WSSConstants.BSPRule bspRule) throws WSSecurityException {
        if (keyInfoType != null) {
            if (keyInfoType.getContent().size() != 1) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R5424);
            }
            SecurityTokenReferenceType securityTokenReferenceType = XMLSecurityUtils.getQNameType(keyInfoType.getContent(),
                    WSSConstants.TAG_wsse_SecurityTokenReference);
            if (securityTokenReferenceType == null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R5426);
            }
        }

        if (referenceList != null) {
            List<JAXBElement<ReferenceType>> references = referenceList.getDataReferenceOrKeyReference();
            Iterator<JAXBElement<ReferenceType>> referenceTypeIterator = references.iterator();
            while (referenceTypeIterator.hasNext()) {
                ReferenceType referenceType = referenceTypeIterator.next().getValue();
                if (!referenceType.getURI().startsWith("#")) {
                    securityContext.handleBSPRule(bspRule);
                }
            }
        }
    }

    protected void handleEncryptedContent(InputProcessorChain inputProcessorChain, XMLSecStartElement parentStartXMLEvent,
                                          SecurityToken securityToken) throws XMLSecurityException {

        final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
        List<QName> elementPath = parentStartXMLEvent.getElementPath();
        if (elementPath.size() == 2 && WSSUtils.isInSOAPBody(elementPath)) {
            //soap:body content encryption counts as EncryptedPart
            EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                    new EncryptedPartSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
            encryptedPartSecurityEvent.setElementPath(elementPath);
            encryptedPartSecurityEvent.setXmlSecEvent(parentStartXMLEvent);
            ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptedPartSecurityEvent);
        } else {
            ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                    new ContentEncryptedElementSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
            contentEncryptedElementSecurityEvent.setElementPath(elementPath);
            contentEncryptedElementSecurityEvent.setXmlSecEvent(parentStartXMLEvent);
            ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(contentEncryptedElementSecurityEvent);
        }
    }

    @Override
    protected AbstractDecryptedEventReaderInputProcessor newDecryptedEventReaderInputProccessor(
            boolean encryptedHeader, XMLSecStartElement xmlSecStartElement, EncryptedDataType currentEncryptedDataType,
            SecurityToken securityToken, SecurityContext securityContext) throws WSSecurityException {

        String encryptionAlgorithm = currentEncryptedDataType.getEncryptionMethod().getAlgorithm();
        if (!WSSConstants.NS_XENC_TRIBLE_DES.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC_AES128.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC_AES256.equals(encryptionAlgorithm)) {
            ((WSSecurityContext) securityContext).handleBSPRule(WSSConstants.BSPRule.R5620);
        }

        return new DecryptedEventReaderInputProcessor(getSecurityProperties(),
                SecurePart.Modifier.getModifier(currentEncryptedDataType.getType()),
                encryptedHeader, xmlSecStartElement, this, securityToken);
    }

    @Override
    protected void handleSecurityToken(SecurityToken securityToken, SecurityContext securityContext,
                                       EncryptedDataType encryptedDataType) throws XMLSecurityException {
        securityToken.addTokenUsage(SecurityToken.TokenUsage.Encryption);
        TokenSecurityEvent tokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
        securityContext.registerSecurityEvent(tokenSecurityEvent);
    }

    /*
   <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncDataId-1612925417" Type="http://www.w3.org/2001/04/xmlenc#Content">
       <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
       <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
           <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
               <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398" />
           </wsse:SecurityTokenReference>
       </ds:KeyInfo>
       <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
           <xenc:CipherValue xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
           ...
           </xenc:CipherValue>
       </xenc:CipherData>
   </xenc:EncryptedData>
    */

    /**
     * The DecryptedEventReaderInputProcessor reads the decrypted stream with a StAX reader and
     * forwards the generated XMLEvents
     */
    class DecryptedEventReaderInputProcessor extends AbstractDecryptedEventReaderInputProcessor {

        DecryptedEventReaderInputProcessor(
                XMLSecurityProperties securityProperties, SecurePart.Modifier encryptionModifier,
                boolean encryptedHeader, XMLSecStartElement xmlSecStartElement,
                DecryptInputProcessor decryptInputProcessor,
                SecurityToken securityToken
        ) {
            super(securityProperties, encryptionModifier, encryptedHeader, xmlSecStartElement, decryptInputProcessor, securityToken);
        }

        protected void handleEncryptedElement(InputProcessorChain inputProcessorChain, XMLSecStartElement xmlSecStartElement,
                                              SecurityToken securityToken) throws XMLSecurityException {
            //fire a SecurityEvent:
            final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
            List<QName> elementPath = xmlSecStartElement.getElementPath();
            if (elementPath.size() == 3 && WSSUtils.isInSOAPHeader(elementPath)) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                        new EncryptedPartSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
                encryptedPartSecurityEvent.setElementPath(elementPath);
                encryptedPartSecurityEvent.setXmlSecEvent(xmlSecStartElement);
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptedPartSecurityEvent);
            } else {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent =
                        new EncryptedElementSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
                encryptedElementSecurityEvent.setElementPath(elementPath);
                encryptedElementSecurityEvent.setXmlSecEvent(xmlSecStartElement);
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptedElementSecurityEvent);
            }
        }
    }
}
