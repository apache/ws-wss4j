/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.interceptor;

import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.StaxInInterceptor;
import org.swssf.WSSec;
import org.swssf.ext.Constants;
import org.swssf.ext.InboundWSSec;
import org.swssf.ext.SecurityProperties;
import org.swssf.ext.WSSecurityException;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityInInterceptor extends AbstractSoapInterceptor {

    private static final Set<QName> HEADERS = new HashSet<QName>();

    static {
        HEADERS.add(Constants.TAG_wsse_Security);
        HEADERS.add(Constants.TAG_xenc_EncryptedData);
    }

    private InboundWSSec inboundWSSec;

    public SecurityInInterceptor(String p, SecurityProperties securityProperties) throws Exception {
        super(p);
        getAfter().add(StaxInInterceptor.class.getName());

        inboundWSSec = WSSec.getInboundWSSec(securityProperties);
    }

    public void handleMessage(SoapMessage soapMessage) throws Fault {

        XMLStreamReader originalXmlStreamReader = soapMessage.getContent(XMLStreamReader.class);
        XMLStreamReader newXmlStreamReader = null;

        final List<SecurityEvent> incomingSecurityEventList = new ArrayList<SecurityEvent>();
        SecurityEventListener securityEventListener = new SecurityEventListener() {
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
            //todo correct faults per WSS-spec
        } catch (WSSecurityException e) {
            throw new SoapFault("Invalid security", soapMessage.getVersion().getSender());
        } catch (XMLStreamException e) {
            throw new SoapFault("Invalid security", soapMessage.getVersion().getReceiver());
        }
    }

    public Set<QName> getUnderstoodHeaders() {
        return HEADERS;
    }
}
