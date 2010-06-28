package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.test.utils.StAX2DOM;
import ch.gigerstyle.xmlsec.test.utils.XmlReaderToWriter;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 1:30:22 PM
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
public class SimpleTest extends AbstractTestBase {

    @Test
    public void testInOutputChain() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));

        SecurityProperties securityProperties = new SecurityProperties();

        securityProperties.setOutAction(new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT});
        //securityProperties.setDecryptionAliasPassword("refApp9876".toCharArray());
        //securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        //securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.addEncryptionSecurePart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Content"));
        securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        securityProperties.setEncryptionUser("receiver");

        securityProperties.addSignaturePart(new SecurePart("simpleType", "http://www.w3.org/1999/XMLSchema", "Element"));
        securityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), "Element"));
        securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
        securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());

        securityProperties.setTimestampTTL(300);

        OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);

        XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);

/*        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new StaxSource(xmlStreamReader), new StAXResult(xmlStreamWriter));
  */
/*        XMLStreamReader2 xmlStreamReader2 = (XMLStreamReader2) XMLInputFactory2.newFactory().createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
        while (xmlStreamReader2.hasNext()) {
            xmlStreamReader2.next();
            Stax2WriterAdapter.wrapIfNecessary(xmlStreamWriter).copyEventFromReader(xmlStreamReader2, false);
        }
        */


        long start = System.currentTimeMillis();

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        //XMLStreamHelper.copy(xmlStreamReader, xmlStreamWriter, false);
        xmlStreamWriter.close();

        System.out.println("Time to Encrypt: " + (System.currentTimeMillis() - start));

        baos.writeTo(System.out);

        System.out.flush();

        start = System.currentTimeMillis();

        securityProperties.setDecryptionAliasPassword("refApp9876".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundXMLSec xmlSecIn = XMLSec.getInboundXMLSec(securityProperties);
        XMLStreamReader outXmlStreamReader = xmlSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
        System.out.println("Time: " + (System.currentTimeMillis() - start));
        System.out.println("");
        System.out.flush();
        //xmlStreamReader.close();
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        while (outXmlStreamReader.hasNext() && outXmlStreamReader.next() != XMLStreamConstants.START_ELEMENT) {
        }
        StAX2DOM.readDocElements(document, document, outXmlStreamReader, false, false);

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(System.out));

        /*transformer.transform(new DOMSource(document), new StreamResult(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                //To change body of implemented methods use File | Settings | File Templates.
            }
        }));
        */
    }

}
