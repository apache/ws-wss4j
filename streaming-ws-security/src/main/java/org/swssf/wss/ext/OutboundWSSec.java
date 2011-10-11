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
package org.swssf.wss.ext;

import org.swssf.wss.impl.WSSDocumentContextImpl;
import org.swssf.wss.impl.WSSecurityContextImpl;
import org.swssf.wss.impl.processor.output.*;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SecurityEventListener;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.impl.OutputProcessorChainImpl;
import org.swssf.xmlsec.impl.XMLSecurityStreamWriter;
import org.swssf.xmlsec.impl.processor.output.FinalOutputProcessor;

import javax.xml.stream.XMLStreamWriter;
import java.io.OutputStream;
import java.util.List;

/**
 * Outbound Streaming-WebService-Security
 * An instance of this class can be retrieved over the WSSec class
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class OutboundWSSec {

    private WSSSecurityProperties securityProperties;

    public OutboundWSSec(WSSSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents) throws WSSecurityException {
        return processOutMessage(outputStream, encoding, requestSecurityEvents, null);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents, SecurityEventListener securityEventListener) throws WSSecurityException {

        final WSSecurityContextImpl securityContextImpl = new WSSecurityContextImpl();
        securityContextImpl.putList(SecurityEvent.class, requestSecurityEvents);
        securityContextImpl.setSecurityEventListener(securityEventListener);
        final WSSDocumentContextImpl documentContext = new WSSDocumentContextImpl();
        documentContext.setEncoding(encoding);

        OutputProcessorChainImpl processorChain = new OutputProcessorChainImpl(securityContextImpl, documentContext);

        try {
            processorChain.addProcessor(new SecurityHeaderOutputProcessor(securityProperties, null));
            //todo some combinations are not possible atm: eg Action.SIGNATURE and Action.USERNAMETOKEN_SIGNED
            //todo they use the same signaure parts
            for (int i = 0; i < securityProperties.getOutAction().length; i++) {
                XMLSecurityConstants.Action action = securityProperties.getOutAction()[i];
                if (action.equals(WSSConstants.TIMESTAMP)) {
                    processorChain.addProcessor(new TimestampOutputProcessor(securityProperties, action));
                } else if (action.equals(WSSConstants.SIGNATURE)) {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    SignatureEndingOutputProcessor signatureEndingOutputProcessor = new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor);
                    signatureEndingOutputProcessor.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
                    processorChain.addProcessor(signatureEndingOutputProcessor);
                } else if (action.equals(WSSConstants.ENCRYPT)) {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptOutputProcessor(securityProperties, action));
                    org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor encryptEndingOutputProcessor = new org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor(securityProperties, action);
                    encryptEndingOutputProcessor.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
                    processorChain.addProcessor(encryptEndingOutputProcessor);
                } else if (action.equals(WSSConstants.USERNAMETOKEN)) {
                    UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(usernameTokenOutputProcessor);
                } else if (action.equals(WSSConstants.USERNAMETOKEN_SIGNED)) {
                    processorChain.addProcessor(new UsernameTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    SignatureEndingOutputProcessor signatureEndingOutputProcessor = new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor);
                    signatureEndingOutputProcessor.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
                    processorChain.addProcessor(signatureEndingOutputProcessor);
                } else if (action.equals(WSSConstants.SIGNATURE_CONFIRMATION)) {
                    SignatureConfirmationOutputProcessor signatureConfirmationOutputProcessor = new SignatureConfirmationOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureConfirmationOutputProcessor);
                } else if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                        processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    } else if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.SecurityContextToken) {
                        processorChain.addProcessor(new SecurityContextTokenOutputProcessor(securityProperties, action));
                    }
                    processorChain.addProcessor(new DerivedKeyTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    SignatureEndingOutputProcessor signatureEndingOutputProcessor = new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor);
                    signatureEndingOutputProcessor.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
                    processorChain.addProcessor(signatureEndingOutputProcessor);
                } else if (action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                        processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    } else if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.SecurityContextToken) {
                        processorChain.addProcessor(new SecurityContextTokenOutputProcessor(securityProperties, action));
                    }
                    processorChain.addProcessor(new DerivedKeyTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptOutputProcessor(securityProperties, action));
                    org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor encryptEndingOutputProcessor = new org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor(securityProperties, action);
                    encryptEndingOutputProcessor.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
                    processorChain.addProcessor(encryptEndingOutputProcessor);
                } else if (action.equals(WSSConstants.SAML_TOKEN_SIGNED)) {
                    processorChain.addProcessor(new SAMLTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    SignatureEndingOutputProcessor signatureEndingOutputProcessor = new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor);
                    signatureEndingOutputProcessor.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
                    processorChain.addProcessor(signatureEndingOutputProcessor);
                } else if (action.equals(WSSConstants.SAML_TOKEN_UNSIGNED)) {
                    processorChain.addProcessor(new SAMLTokenOutputProcessor(securityProperties, action));
                }
            }

            processorChain.addProcessor(new FinalOutputProcessor(outputStream, encoding, securityProperties, null));
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
        return new XMLSecurityStreamWriter(processorChain);
    }
}
