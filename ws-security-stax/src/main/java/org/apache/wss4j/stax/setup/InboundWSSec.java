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
package org.apache.wss4j.stax.setup;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.InboundWSSecurityContextImpl;
import org.apache.wss4j.stax.impl.WSSecurityStreamReader;
import org.apache.wss4j.stax.impl.processor.input.OperationInputProcessor;
import org.apache.wss4j.stax.impl.processor.input.SecurityHeaderInputProcessor;
import org.apache.wss4j.stax.impl.processor.input.SignatureConfirmationInputProcessor;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InputProcessor;
import org.apache.xml.security.stax.impl.DocumentContextImpl;
import org.apache.xml.security.stax.impl.InputProcessorChainImpl;
import org.apache.xml.security.stax.impl.processor.input.LogInputProcessor;
import org.apache.xml.security.stax.impl.processor.input.XMLEventReaderInputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

/**
 * Inbound Streaming-WebService-Security
 * An instance of this class can be retrieved over the WSSec class
 */
public class InboundWSSec {

    protected static final transient org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(InboundWSSec.class);

    private static final XMLInputFactory XML_INPUT_FACTORY = XMLInputFactory.newInstance();

    static {
        XML_INPUT_FACTORY.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XML_INPUT_FACTORY.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        try {
            XML_INPUT_FACTORY.setProperty("org.codehaus.stax2.internNames", true);
            XML_INPUT_FACTORY.setProperty("org.codehaus.stax2.internNsUris", true);
            XML_INPUT_FACTORY.setProperty("org.codehaus.stax2.preserveLocation", false);
        } catch (IllegalArgumentException e) {
            LOG.debug(e.getMessage(), e);
            //ignore
        }
    }

    private final WSSSecurityProperties securityProperties;
    private final boolean initiator;
    private final boolean returnSecurityError;

    public InboundWSSec(WSSSecurityProperties securityProperties) {
        this(securityProperties, false, false);
    }

    public InboundWSSec(WSSSecurityProperties securityProperties, boolean initiator,
                        boolean returnSecurityError) {
        this.securityProperties = securityProperties;
        this.initiator = initiator;
        this.returnSecurityError = returnSecurityError;
    }

    /**
     * Warning:
     * configure your xmlStreamReader correctly. Otherwise you can create a security hole.
     * At minimum configure the following properties:
     * xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
     * xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(8192));
     * <p/>
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param xmlStreamReader The original XMLStreamReader
     * @return A new XMLStreamReader which does transparently the security processing.
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws XMLSecurityException
     */
    public XMLStreamReader processInMessage(
            XMLStreamReader xmlStreamReader) throws XMLStreamException, WSSecurityException {
        return this.processInMessage(xmlStreamReader, null, (SecurityEventListener)null);
    }

    /**
     * Warning:
     * configure your xmlStreamReader correctly. Otherwise you can create a security hole.
     * At minimum configure the following properties:
     * xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
     * xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(8192));
     * <p/>
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param xmlStreamReader       The original XMLStreamReader
     * @return A new XMLStreamReader which does transparently the security processing.
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws XMLSecurityException
     */
    public XMLStreamReader processInMessage(
            XMLStreamReader xmlStreamReader, List<SecurityEvent> requestSecurityEvents
    ) throws XMLStreamException, WSSecurityException {
        return this.processInMessage(xmlStreamReader, requestSecurityEvents, (SecurityEventListener)null);
    }

    /**
     * Warning:
     * configure your xmlStreamReader correctly. Otherwise you can create a security hole.
     * At minimum configure the following properties:
     * xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
     * xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(8192));
     * <p/>
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param xmlStreamReader       The original XMLStreamReader
     * @param securityEventListener A SecurityEventListener to receive security-relevant events.
     * @return A new XMLStreamReader which does transparently the security processing.
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws XMLSecurityException
     */
    public XMLStreamReader processInMessage(
            XMLStreamReader xmlStreamReader, List<SecurityEvent> requestSecurityEvents,
            SecurityEventListener securityEventListener) throws XMLStreamException, WSSecurityException {
        return this.processInMessage(xmlStreamReader, requestSecurityEvents,
                                     Collections.singletonList(securityEventListener));
    }
    /**
     * Warning:
     * configure your xmlStreamReader correctly. Otherwise you can create a security hole.
     * At minimum configure the following properties:
     * xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
     * xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
     * xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(8192));
     * <p/>
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param xmlStreamReader       The original XMLStreamReader
     * @param securityEventListeners A list of SecurityEventListeners to receive security-relevant events.
     * @return A new XMLStreamReader which does transparently the security processing.
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws XMLSecurityException
     */
    public XMLStreamReader processInMessage(
            XMLStreamReader xmlStreamReader, List<SecurityEvent> requestSecurityEvents,
            List<SecurityEventListener> securityEventListeners) throws XMLStreamException, WSSecurityException {

        if (requestSecurityEvents == null) {
            requestSecurityEvents = Collections.emptyList();
        }

        final InboundWSSecurityContextImpl securityContextImpl = new InboundWSSecurityContextImpl();
        securityContextImpl.putList(SecurityEvent.class, requestSecurityEvents);
        if (securityEventListeners != null) {
            for (SecurityEventListener securityEventListener : securityEventListeners) {
                securityContextImpl.addSecurityEventListener(securityEventListener);
            }
        }
        securityContextImpl.ignoredBSPRules(this.securityProperties.getIgnoredBSPRules());
        securityContextImpl.setDisableBSPEnforcement(this.securityProperties.isDisableBSPEnforcement());
        securityContextImpl.setAllowRSA15KeyTransportAlgorithm(this.securityProperties.isAllowRSA15KeyTransportAlgorithm());

        if (!requestSecurityEvents.isEmpty()) {
            try {
                Iterator<SecurityEvent> securityEventIterator = requestSecurityEvents.iterator();
                while (securityEventIterator.hasNext()) {
                    SecurityEvent securityEvent = securityEventIterator.next();
                    if (securityEvent instanceof TokenSecurityEvent) {
                        @SuppressWarnings("unchecked")
                        final TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent =
                                (TokenSecurityEvent<? extends InboundSecurityToken>)securityEvent;

                        if (WSSecurityEventConstants.HTTPS_TOKEN.equals(securityEvent.getSecurityEventType())) {
                            securityContextImpl.registerSecurityEvent(securityEvent);
                            securityContextImpl.put(WSSConstants.TRANSPORT_SECURITY_ACTIVE, Boolean.TRUE);
                        }

                        SecurityTokenProvider<InboundSecurityToken> securityTokenProvider =
                                new SecurityTokenProvider<InboundSecurityToken>() {

                            private String id;

                            @Override
                            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {
                                return tokenSecurityEvent.getSecurityToken();
                            }

                            @Override
                            public String getId() {
                                if (this.id == null) {
                                    this.id = tokenSecurityEvent.getSecurityToken().getId();
                                    if (this.id == null) {
                                        this.id = IDGenerator.generateID(null);
                                    }
                                }
                                return this.id;
                            }
                        };
                        securityContextImpl.registerSecurityTokenProvider(securityTokenProvider.getId(), securityTokenProvider);
                    }
                }
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }

        securityContextImpl.put(WSSConstants.XMLINPUTFACTORY, XML_INPUT_FACTORY);

        DocumentContextImpl documentContext = new DocumentContextImpl();
        documentContext.setEncoding(xmlStreamReader.getEncoding() != null ? xmlStreamReader.getEncoding() : StandardCharsets.UTF_8.name());
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(securityContextImpl, documentContext);
        inputProcessorChain.addProcessor(new XMLEventReaderInputProcessor(securityProperties, xmlStreamReader));
        inputProcessorChain.addProcessor(new SecurityHeaderInputProcessor(securityProperties));
        inputProcessorChain.addProcessor(new OperationInputProcessor(securityProperties));

        if (securityProperties.isEnableSignatureConfirmationVerification()) {
            inputProcessorChain.addProcessor(new SignatureConfirmationInputProcessor(securityProperties));
        }

        if (LOG.isTraceEnabled()) {
            LogInputProcessor logInputProcessor = new LogInputProcessor(securityProperties);
            logInputProcessor.addAfterProcessor(SecurityHeaderInputProcessor.class.getName());
            inputProcessorChain.addProcessor(logInputProcessor);
        }

        List<InputProcessor> additionalInputProcessors = securityProperties.getInputProcessorList();
        if (!additionalInputProcessors.isEmpty()) {
            Iterator<InputProcessor> inputProcessorIterator = additionalInputProcessors.iterator();
            while (inputProcessorIterator.hasNext()) {
                InputProcessor inputProcessor = inputProcessorIterator.next();
                inputProcessorChain.addProcessor(inputProcessor);
            }
        }

        return new WSSecurityStreamReader(inputProcessorChain, securityProperties, initiator, returnSecurityError);
    }
}
