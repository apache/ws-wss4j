/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.test;

import org.swssf.WSSec;
import org.swssf.ext.*;
import org.swssf.test.utils.CustomW3CDOMStreamReader;
import org.swssf.test.utils.StAX2DOM;
import org.swssf.test.utils.XmlReaderToWriter;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.*;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class TimestampTest extends AbstractTestBase {

    @Test
    public void testTimestampDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP};
            securityProperties.setOutAction(actions);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(Constants.TAG_wsu_Created.getNamespaceURI(), Constants.TAG_wsu_Created.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(Constants.TAG_wsu_Expires.getNamespaceURI(), Constants.TAG_wsu_Expires.getLocalPart()).item(0);

            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
            GregorianCalendar gregorianCalendarCreated = datatypeFactory.newXMLGregorianCalendar(created.getTextContent()).toGregorianCalendar();
            GregorianCalendar gregorianCalendarExpires = datatypeFactory.newXMLGregorianCalendar(expires.getTextContent()).toGregorianCalendar();

            Assert.assertTrue(gregorianCalendarCreated.before(gregorianCalendarExpires));
            GregorianCalendar now = new GregorianCalendar();
            Assert.assertTrue(now.after(gregorianCalendarCreated));
            Assert.assertTrue(now.before(gregorianCalendarExpires));

            gregorianCalendarCreated.add(Calendar.SECOND, 301);
            Assert.assertTrue(gregorianCalendarCreated.after(gregorianCalendarExpires));
        }

        //done timestamp; now test timestamp verification:
        {
            String action = WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampDefaultConfigurationInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testTimestampTTLOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP};
            securityProperties.setOutAction(actions);
            securityProperties.setTimestampTTL(3600);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(Constants.TAG_wsu_Created.getNamespaceURI(), Constants.TAG_wsu_Created.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(Constants.TAG_wsu_Expires.getNamespaceURI(), Constants.TAG_wsu_Expires.getLocalPart()).item(0);

            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
            GregorianCalendar gregorianCalendarCreated = datatypeFactory.newXMLGregorianCalendar(created.getTextContent()).toGregorianCalendar();
            GregorianCalendar gregorianCalendarExpires = datatypeFactory.newXMLGregorianCalendar(expires.getTextContent()).toGregorianCalendar();

            Assert.assertTrue(gregorianCalendarCreated.before(gregorianCalendarExpires));
            GregorianCalendar now = new GregorianCalendar();
            Assert.assertTrue(now.after(gregorianCalendarCreated));
            Assert.assertTrue(now.before(gregorianCalendarExpires));

            gregorianCalendarCreated.add(Calendar.SECOND, 3601);
            Assert.assertTrue(gregorianCalendarCreated.after(gregorianCalendarExpires));
        }

        //done timestamp; now test timestamp verification:
        {
            String action = WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampExpiredInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        Thread.sleep(1000);

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "invalidTimestamp The security semantics of the message have expired");
            }
        }
    }

    @Test
    public void testTimestampExpiredEncryptedInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.ENCRYPT;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            outboundProperties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        Thread.sleep(1000);

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "invalidTimestamp The security semantics of the message have expired");
            }
        }
    }

    @Test
    public void testTimestampInFutureInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(Constants.TAG_wsu_Created.getNamespaceURI(), Constants.TAG_wsu_Created.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(Constants.TAG_wsu_Expires.getNamespaceURI(), Constants.TAG_wsu_Expires.getLocalPart()).item(0);

            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
            GregorianCalendar gregorianCalendarCreated = new GregorianCalendar();
            gregorianCalendarCreated.add(Calendar.HOUR, 2);
            XMLGregorianCalendar xmlGregorianCalendarCreated = datatypeFactory.newXMLGregorianCalendar(gregorianCalendarCreated);
            created.setTextContent(xmlGregorianCalendarCreated.toXMLFormat());

            GregorianCalendar gregorianCalendarExpires = new GregorianCalendar();
            gregorianCalendarExpires.add(Calendar.HOUR, 2);
            gregorianCalendarExpires.add(Calendar.SECOND, 300);
            XMLGregorianCalendar xmlGregorianCalendarExpires = datatypeFactory.newXMLGregorianCalendar(gregorianCalendarExpires);

            expires.setTextContent(xmlGregorianCalendarExpires.toXMLFormat());
        }

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "invalidTimestamp The security semantics of the message is invalid");
            }
        }
    }

    @Test
    public void testTimestampStrictOffInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        Thread.sleep(1000);

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setStrictTimestampCheck(false);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
    }

    @Test
    public void testTimestampTTLInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "300");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        Thread.sleep(1000);

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setTimestampTTL(1);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "invalidTimestampTTL The security semantics of the message have expired");
            }
        }
    }

    @Test
    public void testTimestampNoCreatedDateInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE && ((Element) node).getLocalName().equals("Created")) {
                    node.getParentNode().removeChild(node);
                }
            }
        }

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Throwable throwable = e.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof WSSecurityException);
                throwable = throwable.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof ParseException);
                Assert.assertEquals(throwable.getMessage(), "Element \"Created\" is missing");
            }
        }
    }

    @Test
    public void testTimestampNoExpiresDateInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE && ((Element) node).getLocalName().equals("Expires")) {
                    node.getParentNode().removeChild(node);
                }
            }
        }

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testTimestampNoChildsInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            List<Node> nodesToRemove = new ArrayList<Node>();
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE
                        && (((Element) node).getLocalName().equals("Created")) || ((Element) node).getLocalName().equals("Expires")) {
                    nodesToRemove.add(node);
                }
            }
            for (int i = 0; i < nodesToRemove.size(); i++) {
                Node node = nodesToRemove.get(i);
                node.getParentNode().removeChild(node);
            }
        }

        //done timestamp; now test timestamp-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Throwable throwable = e.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof WSSecurityException);
                throwable = throwable.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof ParseException);
                Assert.assertEquals(throwable.getMessage(), "Element \"Created\" is missing");
            }
        }
    }
}
