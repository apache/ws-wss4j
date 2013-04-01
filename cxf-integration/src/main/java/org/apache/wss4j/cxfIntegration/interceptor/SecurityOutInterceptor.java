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
package org.apache.wss4j.cxfIntegration.interceptor;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.AbstractOutDatabindingInterceptor;
import org.apache.cxf.interceptor.AttachmentOutInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.StaxOutInterceptor;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;

import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityOutInterceptor extends AbstractSoapInterceptor {

    public static final SecurityOutInterceptorEndingInterceptor ENDING = new SecurityOutInterceptorEndingInterceptor();
    public static final String OUTPUT_STREAM_HOLDER = SecurityOutInterceptor.class.getName() + ".outputstream";
    public static final String FORCE_START_DOCUMENT = "org.apache.cxf.stax.force-start-document";
    private final OutboundWSSec outboundWSSec;

    public SecurityOutInterceptor(String p, WSSSecurityProperties securityProperties) throws Exception {
        super(p);
        getBefore().add(StaxOutInterceptor.class.getName());

        outboundWSSec = WSSec.getOutboundWSSec(securityProperties);
    }

    @Override
    public void handleMessage(SoapMessage soapMessage) throws Fault {

        OutputStream os = soapMessage.getContent(OutputStream.class);

        String encoding = getEncoding(soapMessage);

        final List<SecurityEvent> outgoingSecurityEventList = new ArrayList<SecurityEvent>();
        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                outgoingSecurityEventList.add(securityEvent);
            }
        };
        soapMessage.getExchange().put(SecurityEvent.class.getName() + ".out", outgoingSecurityEventList);

        XMLStreamWriter newXMLStreamWriter;
        try {
            final List<SecurityEvent> requestSecurityEvents = (List<SecurityEvent>) soapMessage.getExchange().get(SecurityEvent.class.getName() + ".in");
            newXMLStreamWriter = outboundWSSec.processOutMessage(os, encoding, requestSecurityEvents, securityEventListener);
            soapMessage.setContent(XMLStreamWriter.class, newXMLStreamWriter);
        } catch (WSSecurityException e) {
            throw new Fault(e);
        }

        soapMessage.put(AbstractOutDatabindingInterceptor.DISABLE_OUTPUTSTREAM_OPTIMIZATION,
                Boolean.TRUE);
        soapMessage.put(FORCE_START_DOCUMENT, Boolean.TRUE);

        if (MessageUtils.getContextualBoolean(soapMessage, FORCE_START_DOCUMENT, false)) {
            try {
                newXMLStreamWriter.writeStartDocument(encoding, "1.0");
            } catch (XMLStreamException e) {
                throw new Fault(e);
            }
            soapMessage.removeContent(OutputStream.class);
            soapMessage.put(OUTPUT_STREAM_HOLDER, os);
        }

        // Add a final interceptor to write end elements
        soapMessage.getInterceptorChain().add(ENDING);
    }

    private String getEncoding(Message message) {
        Exchange ex = message.getExchange();
        String encoding = (String) message.get(Message.ENCODING);
        if (encoding == null && ex.getInMessage() != null) {
            encoding = (String) ex.getInMessage().get(Message.ENCODING);
            message.put(Message.ENCODING, encoding);
        }

        if (encoding == null) {
            encoding = "UTF-8";
            message.put(Message.ENCODING, encoding);
        }
        return encoding;
    }

    public static class SecurityOutInterceptorEndingInterceptor extends AbstractPhaseInterceptor<Message> {

        public SecurityOutInterceptorEndingInterceptor() {
            super(Phase.PRE_STREAM_ENDING);
            getAfter().add(AttachmentOutInterceptor.AttachmentOutEndingInterceptor.class.getName());
        }

        @Override
        public void handleMessage(Message message) throws Fault {
            try {
                XMLStreamWriter xtw = message.getContent(XMLStreamWriter.class);
                if (xtw != null) {
                    xtw.writeEndDocument();
                    xtw.flush();
                    xtw.close();
                }

                OutputStream os = (OutputStream) message.get(OUTPUT_STREAM_HOLDER);
                if (os != null) {
                    message.setContent(OutputStream.class, os);
                }
                message.removeContent(XMLStreamWriter.class);
            } catch (XMLStreamException e) {
                throw new Fault(e);
            }
        }
    }
}
