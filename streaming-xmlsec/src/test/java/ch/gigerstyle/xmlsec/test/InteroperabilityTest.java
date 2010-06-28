package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.InboundXMLSec;
import ch.gigerstyle.xmlsec.SecurityProperties;
import ch.gigerstyle.xmlsec.XMLSec;
import ch.gigerstyle.xmlsec.test.utils.StAX2DOM;
import com.sun.xml.ws.streaming.DOMStreamReader;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSS4JHandler;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.rpc.handler.HandlerInfo;
import javax.xml.rpc.handler.MessageContext;
import javax.xml.rpc.handler.soap.SOAPMessageContext;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPMessage;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

/**
 * User: giger
 * Date: Jun 24, 2010
 * Time: 6:30:35 PM
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
public class InteroperabilityTest extends AbstractTestBase {

    @Test(invocationCount = 1)
    public void testInteroperability() throws Exception {

        WSS4JHandler wss4JHandler = new WSS4JHandler();

        HandlerInfo handlerInfo = new HandlerInfo();
        wss4JHandler.init(handlerInfo);
        MessageContext messageContext = new SOAPMessageContext() {

            private Map properties = new HashMap();

            public void setProperty(String s, Object o) {
                properties.put(s, o);
            }

            public Object getProperty(String s) {
                return properties.get(s);
            }

            public void removeProperty(String s) {
                properties.remove(s);
            }

            public boolean containsProperty(String s) {
                return properties.containsKey(s);
            }

            public Iterator getPropertyNames() {
                return properties.keySet().iterator();
            }

            public SOAPMessage getMessage() {
                try {
                    MessageFactory messageFactory = MessageFactory.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL);
                    SOAPMessage soapMessage = messageFactory.createMessage();
                    soapMessage.getSOAPPart().setContent(new StreamSource(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml")));
                    return soapMessage;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            public void setMessage(SOAPMessage soapMessage) {
                throw new UnsupportedOperationException();
            }

            public String[] getRoles() {
                return new String[0];  //To change body of implemented methods use File | Settings | File Templates.
            }
        };


        handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTION, WSHandlerConstants.NO_SERIALIZATION + " " + WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.USER, "transmitter");
        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "refApp9876");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "1234567890");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "refApp9876");
        messageContext.setProperty(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.setProperty("" + sigProperties.hashCode(), sigProperties);

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        wss4JHandler.doSender(messageContext, requestData, false);


        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundXMLSec(securityProperties);
        XMLStreamReader outXmlStreamReader = inboundXMLSec.processInMessage(new DOMStreamReader((Document) messageContext.getProperty(WSHandlerConstants.SND_SECURITY)));

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        while (outXmlStreamReader.hasNext() && outXmlStreamReader.next() != XMLStreamConstants.START_ELEMENT) {
        }
        StAX2DOM.readDocElements(document, document, outXmlStreamReader, false, false);
        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }
}
