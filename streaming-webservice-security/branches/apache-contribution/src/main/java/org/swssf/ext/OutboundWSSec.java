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
package org.swssf.ext;

import com.sun.istack.Nullable;
import org.swssf.impl.DocumentContextImpl;
import org.swssf.impl.OutputProcessorChainImpl;
import org.swssf.impl.XMLSecurityStreamWriter;
import org.swssf.impl.processor.output.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;

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

    private SecurityProperties securityProperties;

    public OutboundWSSec(SecurityProperties securityProperties) {
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
    public XMLStreamWriter processOutMessage(OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents, @Nullable SecurityEventListener securityEventListener) throws WSSecurityException {

        final SecurityContextImpl securityContextImpl = new SecurityContextImpl();
        securityContextImpl.putList(SecurityEvent.class, requestSecurityEvents);
        securityContextImpl.setSecurityEventListener(securityEventListener);
        final DocumentContextImpl documentContext = new DocumentContextImpl();
        documentContext.setEncoding(encoding);

        OutputProcessorChainImpl processorChain = new OutputProcessorChainImpl(securityContextImpl, documentContext);
        processorChain.addProcessor(new SecurityHeaderOutputProcessor(securityProperties, null));
        //todo some combinations are not possible atm: eg Action.SIGNATURE and Action.USERNAMETOKEN_SIGNED
        //todo they use the same signaure parts
        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            Constants.Action action = securityProperties.getOutAction()[i];
            switch (action) {
                case TIMESTAMP: {
                    processorChain.addProcessor(new TimestampOutputProcessor(securityProperties, action));
                    break;
                }
                case SIGNATURE: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case ENCRYPT: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptEndingOutputProcessor(securityProperties, action));
                    break;
                }
                case USERNAMETOKEN: {
                    UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(usernameTokenOutputProcessor);
                    break;
                }
                case USERNAMETOKEN_SIGNED: {
                    processorChain.addProcessor(new UsernameTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case SIGNATURE_CONFIRMATION: {
                    SignatureConfirmationOutputProcessor signatureConfirmationOutputProcessor = new SignatureConfirmationOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureConfirmationOutputProcessor);
                    break;
                }
                case SIGNATURE_WITH_DERIVED_KEY: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.EncryptedKey) {
                        processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    } else if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.SecurityContextToken) {
                        processorChain.addProcessor(new SecurityContextTokenOutputProcessor(securityProperties, action));
                    }
                    processorChain.addProcessor(new DerivedKeyTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case ENCRYPT_WITH_DERIVED_KEY: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.EncryptedKey) {
                        processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    } else if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.SecurityContextToken) {
                        processorChain.addProcessor(new SecurityContextTokenOutputProcessor(securityProperties, action));
                    }
                    processorChain.addProcessor(new DerivedKeyTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptEndingOutputProcessor(securityProperties, action));
                    break;
                }
                case SAML_TOKEN_SIGNED: {
                    processorChain.addProcessor(new SAMLTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case SAML_TOKEN_UNSIGNED: {
                    processorChain.addProcessor(new SAMLTokenOutputProcessor(securityProperties, action));
                }
            }
        }

        processorChain.addProcessor(new FinalOutputProcessor(outputStream, encoding, securityProperties, null));
        return new XMLSecurityStreamWriter(processorChain);
    }
}
