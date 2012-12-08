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
package org.swssf.cxfIntegration.interceptor;

import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.ServiceInvokerInterceptor;
import org.apache.cxf.interceptor.StaxInInterceptor;

import org.apache.cxf.phase.Phase;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.WSSec;
import org.apache.ws.security.stax.ext.InboundWSSec;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;

import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityInInterceptor extends AbstractSoapInterceptor {

    private static final Set<QName> HEADERS = new HashSet<QName>();

    static {
        HEADERS.add(WSSConstants.TAG_wsse_Security);
        HEADERS.add(WSSConstants.TAG_xenc_EncryptedData);
    }

    private final InboundWSSec inboundWSSec;

    public SecurityInInterceptor(String p, WSSSecurityProperties securityProperties) throws Exception {
        super(p);
        getAfter().add(StaxInInterceptor.class.getName());

        inboundWSSec = WSSec.getInboundWSSec(securityProperties);
    }

    @Override
    public void handleMessage(SoapMessage soapMessage) throws Fault {

        XMLStreamReader originalXmlStreamReader = soapMessage.getContent(XMLStreamReader.class);
        XMLStreamReader newXmlStreamReader;

        final List<SecurityEvent> incomingSecurityEventList = new LinkedList<SecurityEvent>();
        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                incomingSecurityEventList.add(securityEvent);
            }
        };
        soapMessage.getExchange().put(SecurityEvent.class.getName() + ".in", incomingSecurityEventList);

        try {
            @SuppressWarnings("unchecked")
            final List<SecurityEvent> requestSecurityEvents = (List<SecurityEvent>) soapMessage.getExchange().get(SecurityEvent.class.getName() + ".out");
            newXmlStreamReader = inboundWSSec.processInMessage(originalXmlStreamReader, requestSecurityEvents, securityEventListener);
            soapMessage.setContent(XMLStreamReader.class, newXmlStreamReader);

            //workaround: CXF seems not to call xmlstreamReader.close() which is essential to complete
            //security processing. So we add another interceptor which does it.
            AbstractSoapInterceptor abstractSoapInterceptor = new AbstractSoapInterceptor(Phase.PRE_INVOKE) {

                @Override
                public void handleMessage(SoapMessage message) throws Fault {
                    XMLStreamReader xmlStreamReader = message.getContent(XMLStreamReader.class);
                    try {
                        xmlStreamReader.close();
                    } catch (XMLStreamException e) {
                        throw new SoapFault("unexpected service error", SoapFault.FAULT_CODE_SERVER);
                    }
                }
            };
            abstractSoapInterceptor.addBefore(ServiceInvokerInterceptor.class.getName());
            soapMessage.getInterceptorChain().add(abstractSoapInterceptor);

            //Warning: The exceptions which can occur here are not security relevant exceptions but configuration-errors.
            //To catch security relevant exceptions you have to catch them e.g.in the FaultOutInterceptor.
            //Why? Because we do streaming security. This interceptor doesn't handle the ws-security stuff but just
            //setup the relevant stuff for it. Exceptions will be thrown as a wrapped XMLStreamException during further
            //processing in the WS-Stack.

        } catch (WSSecurityException e) {
            throw new SoapFault("unexpected service error", SoapFault.FAULT_CODE_SERVER);
        } catch (XMLStreamException e) {
            throw new SoapFault("unexpected service error", SoapFault.FAULT_CODE_SERVER);
        }
    }

    @Override
    public Set<QName> getUnderstoodHeaders() {
        return HEADERS;
    }
}
