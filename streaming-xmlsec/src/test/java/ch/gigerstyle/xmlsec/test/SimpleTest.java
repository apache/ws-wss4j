package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.test.utils.XMLStreamHelper;
import ch.gigerstyle.xmlsec.test.utils.XmlReaderToWriter;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLStreamReader2;
import org.codehaus.stax2.ri.Stax2WriterAdapter;
import org.testng.annotations.Test;
import org.w3c.dom.*;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

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
public class SimpleTest {

    private static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();

    class Callback implements CallbackHandler {
        public void handle(javax.security.auth.callback.Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];

            if (pc.getUsage() == WSPasswordCallback.DECRYPT || pc.getUsage() == WSPasswordCallback.SIGNATURE) {
                pc.setPassword("refApp9876");
            } else {
                throw new UnsupportedCallbackException(pc, "Unrecognized Callback");
            }
        }
    }

    @Test
    public void testInputChain() throws Exception {
        for (int i = 0; i < 10; i++) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/sigenc.xml"));
            //XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/ICHAGCompany-3000-sig-enc.xml"));

            long start = System.currentTimeMillis();

            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setDecryptionAliasPassword("refApp9876".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new Callback());
            XMLSec xmlSec = new XMLSec(securityProperties);
            XMLStreamReader outXmlStreamReader = xmlSec.processInMessage(xmlStreamReader);
            System.out.println("Time: " + (System.currentTimeMillis() - start));
            System.out.println("");
            System.out.flush();
            //xmlStreamReader.close();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.newDocument();
            outXmlStreamReader.next();
            readDocElements(document, document, outXmlStreamReader, false, false);

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            //transformer.transform(new DOMSource(document), new StreamResult(System.out));

            transformer.transform(new DOMSource(document), new StreamResult(new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    //To change body of implemented methods use File | Settings | File Templates.
                }
            }));

        }
    }

    @Test
    public void testOutputChain() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));

        SecurityProperties securityProperties = new SecurityProperties();
        //securityProperties.setDecryptionAliasPassword("refApp9876".toCharArray());
        //securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        //securityProperties.setCallbackHandler(new Callback());
        securityProperties.addEncryptionSecurePart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Content"));
        securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        XMLSec xmlSec = new XMLSec(securityProperties);

        XMLStreamWriter xmlStreamWriter = xmlSec.processOutMessage(baos);

/*        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new StaxSource(xmlStreamReader), new StAXResult(xmlStreamWriter));
  */
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        baos.writeTo(System.out);

        System.out.flush();
    }

    @Test
    public void testInOutputChain() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));

        SecurityProperties securityProperties = new SecurityProperties();
        //securityProperties.setDecryptionAliasPassword("refApp9876".toCharArray());
        //securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        //securityProperties.setCallbackHandler(new Callback());
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
        securityProperties.setCallbackHandler(new Callback());

        securityProperties.setTimestampTTL(300);

        XMLSec xmlSecOut = new XMLSec(securityProperties);

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
        securityProperties.setCallbackHandler(new Callback());
        XMLSec xmlSecIn = new XMLSec(securityProperties);
        XMLStreamReader outXmlStreamReader = xmlSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
        System.out.println("Time: " + (System.currentTimeMillis() - start));
        System.out.println("");
        System.out.flush();
        //xmlStreamReader.close();
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        while (outXmlStreamReader.hasNext() && outXmlStreamReader.next() != XMLStreamConstants.START_ELEMENT){}
        readDocElements(document, document, outXmlStreamReader, false, false);

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

    public static void readDocElements(Document doc, Node parent,
                                       XMLStreamReader reader, boolean repairing, boolean recordLoc)
            throws XMLStreamException {

        int event = reader.getEventType();
        while (reader.hasNext()) {
            switch (event) {
                case XMLStreamConstants.START_ELEMENT:
                    startElement(doc, parent, reader, repairing, recordLoc);

                    if (parent instanceof Document) {
                        return;
                    }
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    return;
                case XMLStreamConstants.NAMESPACE:
                    break;
                case XMLStreamConstants.ATTRIBUTE:
                    break;
                case XMLStreamConstants.CHARACTERS:
                    if (parent != null) {
                        recordLoc = addLocation(doc,
                                parent.appendChild(doc.createTextNode(reader.getText())),
                                reader, recordLoc);
                    }
                    break;
                case XMLStreamConstants.COMMENT:
                    if (parent != null) {
                        parent.appendChild(doc.createComment(reader.getText()));
                    }
                    break;
                case XMLStreamConstants.CDATA:
                    recordLoc = addLocation(doc,
                            parent.appendChild(doc.createCDATASection(reader.getText())),
                            reader, recordLoc);
                    break;
                case XMLStreamConstants.PROCESSING_INSTRUCTION:
                    parent.appendChild(doc.createProcessingInstruction(reader.getPITarget(), reader.getPIData()));
                    break;
                case XMLStreamConstants.ENTITY_REFERENCE:
                    parent.appendChild(doc.createProcessingInstruction(reader.getPITarget(), reader.getPIData()));
                    break;
                default:
                    break;
            }

            if (reader.hasNext()) {
                event = reader.next();
            }
        }
    }

    private static boolean addLocation(Document doc, Node node,
                                       XMLStreamReader reader,
                                       boolean recordLoc) {
        if (recordLoc) {
            Location loc = reader.getLocation();
            if (loc != null && (loc.getColumnNumber() != 0 || loc.getLineNumber() != 0)) {
                try {
                    final int charOffset = loc.getCharacterOffset();
                    final int colNum = loc.getColumnNumber();
                    final int linNum = loc.getLineNumber();
                    final String pubId = loc.getPublicId() == null ? doc.getDocumentURI() : loc.getPublicId();
                    final String sysId = loc.getSystemId() == null ? doc.getDocumentURI() : loc.getSystemId();
                    Location loc2 = new Location() {
                        public int getCharacterOffset() {
                            return charOffset;
                        }

                        public int getColumnNumber() {
                            return colNum;
                        }

                        public int getLineNumber() {
                            return linNum;
                        }

                        public String getPublicId() {
                            return pubId;
                        }

                        public String getSystemId() {
                            return sysId;
                        }
                    };
                    node.setUserData("location", loc2, new UserDataHandler() {
                        public void handle(short operation, String key, Object data, Node src, Node dst) {
                            if (operation == NODE_CLONED) {
                                dst.setUserData(key, data, this);
                            }
                        }
                    });
                } catch (Exception ex) {
                    //possibly not DOM level 3, won't be able to record this then
                    return false;
                }
            }
        }
        return recordLoc;
    }

    /**
     * @param parent
     * @param reader
     * @return
     * @throws XMLStreamException
     */
    private static Element startElement(Document doc,
                                        Node parent,
                                        XMLStreamReader reader,
                                        boolean repairing,
                                        boolean recordLocation)
            throws XMLStreamException {

        Element e = doc.createElementNS(reader.getNamespaceURI(), reader.getLocalName());
        if (reader.getPrefix() != null) {
            e.setPrefix(reader.getPrefix());
        }
        e = (Element) parent.appendChild(e);
        recordLocation = addLocation(doc, e, reader, recordLocation);

        for (int ns = 0; ns < reader.getNamespaceCount(); ns++) {
            String uri = reader.getNamespaceURI(ns);
            String prefix = reader.getNamespacePrefix(ns);

            declare(e, uri, prefix);
        }

        for (int att = 0; att < reader.getAttributeCount(); att++) {
            String name = reader.getAttributeLocalName(att);
            String prefix = reader.getAttributePrefix(att);
            if (prefix != null && prefix.length() > 0) {
                name = prefix + ":" + name;
            }

            Attr attr = doc.createAttributeNS(reader.getAttributeNamespace(att), name);
            attr.setValue(reader.getAttributeValue(att));
            e.setAttributeNode(attr);
        }

        if (repairing && !isDeclared(e, reader.getNamespaceURI(), reader.getPrefix())) {
            declare(e, reader.getNamespaceURI(), reader.getPrefix());
        }

        reader.next();

        readDocElements(doc, e, reader, repairing, recordLocation);

        return e;
    }

    private static final String XML_NS = "http://www.w3.org/2000/xmlns/";

    private static void declare(Element node, String uri, String prefix) {
        String qualname;
        if (prefix != null && prefix.length() > 0) {
            qualname = "xmlns:" + prefix;
        } else {
            qualname = "xmlns";
        }
        Attr attr = node.getOwnerDocument().createAttributeNS(XML_NS, qualname);
        attr.setValue(uri);
        node.setAttributeNodeNS(attr);
    }

    private static boolean isDeclared(Element e, String namespaceURI, String prefix) {
        Attr att;
        if (prefix != null && prefix.length() > 0) {
            att = e.getAttributeNodeNS(XML_NS, prefix);
        } else {
            att = e.getAttributeNode("xmlns");
        }

        if (att != null && att.getNodeValue().equals(namespaceURI)) {
            return true;
        }

        if (e.getParentNode() instanceof Element) {
            return isDeclared((Element) e.getParentNode(), namespaceURI, prefix);
        }

        return false;
    }
}
