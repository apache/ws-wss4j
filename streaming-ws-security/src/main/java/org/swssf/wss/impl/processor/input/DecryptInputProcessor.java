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

import org.swssf.binding.xmldsig.KeyInfoType;
import org.swssf.binding.xmlenc.EncryptedDataType;
import org.swssf.binding.xmlenc.ReferenceList;
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.securityEvent.ContentEncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.EncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.EncryptedPartSecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.processor.input.AbstractDecryptInputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

/**
 * Processor for decryption of EncryptedData XML structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DecryptInputProcessor extends AbstractDecryptInputProcessor {

    public DecryptInputProcessor(ReferenceList referenceList, WSSSecurityProperties securityProperties) {
        super(referenceList, securityProperties);
    }

    public DecryptInputProcessor(KeyInfoType keyInfoType, ReferenceList referenceList,
                                 WSSSecurityProperties securityProperties) {
        super(keyInfoType, referenceList, securityProperties);
    }

    protected void handleEncryptedContent(
            InputProcessorChain inputProcessorChain, XMLEvent xmlEvent, SecurityToken securityToken) throws XMLSecurityException {

        QName parentElement = inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType());
        if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                && ((WSSDocumentContext) inputProcessorChain.getDocumentContext()).isInSOAPBody()) {
            //soap:body content encryption counts as EncryptedPart
            EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                    new EncryptedPartSecurityEvent(securityToken, true, isInSignedContent(inputProcessorChain));
            encryptedPartSecurityEvent.setElement(parentElement);
            ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptedPartSecurityEvent);
        } else {
            ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                    new ContentEncryptedElementSecurityEvent(securityToken, true, isInSignedContent(inputProcessorChain));
            contentEncryptedElementSecurityEvent.setElement(parentElement);
            ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(contentEncryptedElementSecurityEvent);
        }
    }

    @Override
    protected AbstractDecryptedEventReaderInputProcessor newDecryptedEventReaderInputProccessor(
            boolean encryptedHeader, List<ComparableNamespace>[] comparableNamespaceList,
            List<ComparableAttribute>[] comparableAttributeList, EncryptedDataType currentEncryptedDataType, SecurityToken securityToken) {
        return new DecryptedEventReaderInputProcessor(getSecurityProperties(),
                SecurePart.Modifier.getModifier(currentEncryptedDataType.getType()),
                encryptedHeader, comparableNamespaceList, comparableAttributeList,
                this,
                securityToken);
    }

    @Override
    protected void handleSecurityToken(
            SecurityToken securityToken, SecurityContext securityContext, EncryptedDataType encryptedDataType) throws XMLSecurityException {
        TokenSecurityEvent tokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
        tokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        ((WSSecurityContext) securityContext).registerSecurityEvent(tokenSecurityEvent);

        /*AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
       algorithmSuiteSecurityEvent.setAlgorithmURI(encryptedDataType.getEncryptionMethod().getAlgorithm());
       if (securityToken.isAsymmetric()) {
           algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Asym_Key_Wrap);
       } else {
           algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Sym_Key_Wrap);
       }
       ((WSSecurityContext) securityContext).registerSecurityEvent(algorithmSuiteSecurityEvent);*/
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
                boolean encryptedHeader, List<ComparableNamespace>[] namespaceList,
                List<ComparableAttribute>[] attributeList,
                DecryptInputProcessor decryptInputProcessor,
                SecurityToken securityToken
        ) {
            super(securityProperties, encryptionModifier, encryptedHeader, namespaceList, attributeList, decryptInputProcessor, securityToken);
        }

        protected void handleEncryptedElement(InputProcessorChain inputProcessorChain, XMLEvent xmlEvent, SecurityToken securityToken) throws XMLSecurityException {
            //fire a SecurityEvent:
            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                    && ((WSSDocumentContext) inputProcessorChain.getDocumentContext()).isInSOAPHeader()) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                        new EncryptedPartSecurityEvent(securityToken, true, isInSignedContent(inputProcessorChain));
                encryptedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptedPartSecurityEvent);
            } else {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent =
                        new EncryptedElementSecurityEvent(securityToken, true, isInSignedContent(inputProcessorChain));
                encryptedElementSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptedElementSecurityEvent);
            }
        }
    }

    public static boolean isInSignedContent(InputProcessorChain inputProcessorChain) {
        //todo. Also todo: ProtectionOrderAssertionState
        //how can we find out if a signature is done over plaintext or over ciphertext.
        //problem contentEncryptedElements, the signature occurs always firstly...
        return false;
    }
}
