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

import org.swssf.ext.Constants;
import org.swssf.impl.transformer.canonicalizer.Canonicalizer20010315ExclWithCommentsTransformer;
import org.swssf.impl.transformer.canonicalizer.Canonicalizer20010315WithCommentsTransformer;
import org.swssf.test.utils.XMLEventNSAllocator;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class Canonicalizer20010315ExclusiveTest {

    private XMLInputFactory xmlInputFactory;

    @BeforeMethod
    public void setUp() throws Exception {
        this.xmlInputFactory = XMLInputFactory.newFactory();
        this.xmlInputFactory.setEventAllocator(new XMLEventNSAllocator());
    }

    @Test
    public void test221() throws Exception {

        Canonicalizer20010315WithCommentsTransformer c = new Canonicalizer20010315WithCommentsTransformer(null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream("testdata/c14n/inExcl/example2_2_1.xml")
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
        }
        while (xmlEventReader.hasNext()) {

            c.transform(xmlEvent, baos);

            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        byte[] reference = getBytesFromResource(this.getClass().getClassLoader().getResource("testdata/c14n/inExcl/example2_2_1_c14nized.xml"));
        boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (equals == false) {
            System.out.println("Expected:\n" + new String(reference, "UTF-8"));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        }

        assertTrue(equals);
    }

    @Test
    public void test222() throws Exception {

        Canonicalizer20010315WithCommentsTransformer c = new Canonicalizer20010315WithCommentsTransformer(null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream("testdata/c14n/inExcl/example2_2_2.xml")
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
        }
        while (xmlEventReader.hasNext()) {

            c.transform(xmlEvent, baos);

            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        byte[] reference = getBytesFromResource(this.getClass().getClassLoader().getResource("testdata/c14n/inExcl/example2_2_2_c14nized.xml"));
        boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (equals == false) {
            System.out.println("Expected:\n" + new String(reference, "UTF-8"));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        }

        assertTrue(equals);
    }

    @Test
    public void test221excl() throws Exception {

        Canonicalizer20010315ExclWithCommentsTransformer c = new Canonicalizer20010315ExclWithCommentsTransformer(null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream("testdata/c14n/inExcl/example2_2_1.xml")
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
        }
        while (xmlEventReader.hasNext()) {

            c.transform(xmlEvent, baos);

            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        byte[] reference = getBytesFromResource(this.getClass().getClassLoader().getResource("testdata/c14n/inExcl/example2_2_c14nized_exclusive.xml"));
        boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (equals == false) {
            System.out.println("Expected:\n" + new String(reference, "UTF-8"));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        }

        assertTrue(equals);
    }

    @Test
    public void test222excl() throws Exception {

        Canonicalizer20010315ExclWithCommentsTransformer c = new Canonicalizer20010315ExclWithCommentsTransformer(null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream("testdata/c14n/inExcl/example2_2_2.xml")
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
        }
        while (xmlEventReader.hasNext()) {

            c.transform(xmlEvent, baos);

            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        byte[] reference = getBytesFromResource(this.getClass().getClassLoader().getResource("testdata/c14n/inExcl/example2_2_c14nized_exclusive.xml"));
        boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (equals == false) {
            System.out.println("Expected:\n" + new String(reference, "UTF-8"));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        }

        assertTrue(equals);
    }

    @Test
    public void testComplexDocexcl() throws Exception {

        Canonicalizer20010315ExclWithCommentsTransformer c = new Canonicalizer20010315ExclWithCommentsTransformer(null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml")
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(Constants.TAG_soap11_Body)) {
                break;
            }
        }
        while (xmlEventReader.hasNext()) {

            c.transform(xmlEvent, baos);

            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(Constants.TAG_soap11_Body)) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        byte[] reference = getBytesFromResource(this.getClass().getClassLoader().getResource("testdata/c14n/inExcl/plain-soap-c14nized.xml"));
        boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (equals == false) {
            System.out.println("Expected:\n" + new String(reference, "UTF-8"));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        }
/*
        for (int i = 0; i < reference.length; i++) {
            if (reference[i] != baos.toByteArray()[i]) {
                System.out.println("Expected diff: " + new String(reference, i - 10, 20));
                System.out.println("Got diff: " + new String(baos.toByteArray(), i - 10, 20));
                return;
            }
        }
*/
        assertTrue(equals);
    }

    @Test
    public void testNodeSet() throws Exception {

        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

/*        Set nodeSet = new HashSet();
        XMLUtils.getSet
	    (doc.getDocumentElement().getFirstChild(), nodeSet, null, false);
        XMLSignatureInput input = new XMLSignatureInput(nodeSet);
        byte[] bytes = c14n.engineCanonicalize(input, "env ns0 xsi wsu");

*/
        Canonicalizer20010315WithCommentsTransformer c = new Canonicalizer20010315WithCommentsTransformer("env ns0 xsi wsu");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                new StringReader(XML)
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"))) {
                break;
            }
        }

        while (xmlEventReader.hasNext()) {
            c.transform(xmlEvent, baos);
            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"))) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        assertEquals(new String(baos.toByteArray()), c14nXML);
    }
    /*
     private String getAbsolutePath(String path)
     {
           String basedir = System.getProperty("basedir");
           if(basedir != null && !"".equals(basedir)) {
             path = basedir + "/" + path;
           }
           return path;
     }
    */

    public static byte[] getBytesFromResource(URL resource) throws IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream inputStream = resource.openStream();
        try {
            byte buf[] = new byte[1024];
            int len;
            while ((len = inputStream.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }

            return baos.toByteArray();
        } finally {
            inputStream.close();
        }
    }
}