package ch.gigerstyle.xmlsec.interceptor;

import ch.gigerstyle.xmlsec.XMLSec;
import ch.gigerstyle.xmlsec.ext.OutboundXMLSec;
import ch.gigerstyle.xmlsec.ext.SecurityProperties;
import ch.gigerstyle.xmlsec.ext.XMLSecurityException;
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

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.OutputStream;

/**
 * User: giger
 * Date: Oct 24, 2010
 * Time: 2:18:21 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SecurityOutInterceptor extends AbstractSoapInterceptor {

    public static final SecurityOutInterceptorEndingInterceptor ENDING = new SecurityOutInterceptorEndingInterceptor();
    public static final String OUTPUT_STREAM_HOLDER = SecurityOutInterceptor.class.getName() + ".outputstream";
    public static final String FORCE_START_DOCUMENT = "org.apache.cxf.stax.force-start-document";
    private OutboundXMLSec outboundXMLSec;

    public SecurityOutInterceptor(String p, SecurityProperties securityProperties) throws Exception {
        super(p);
        getBefore().add(StaxOutInterceptor.class.getName());

        outboundXMLSec = XMLSec.getOutboundXMLSec(securityProperties);
    }

    public void handleMessage(SoapMessage soapMessage) throws Fault {

        OutputStream os = soapMessage.getContent(OutputStream.class);

        String encoding = getEncoding(soapMessage);

        XMLStreamWriter newXMLStreamWriter;
        //todo encoding
        try {
            newXMLStreamWriter = outboundXMLSec.processOutMessage(os);
            soapMessage.setContent(XMLStreamWriter.class, newXMLStreamWriter);
        } catch (XMLSecurityException e) {
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
