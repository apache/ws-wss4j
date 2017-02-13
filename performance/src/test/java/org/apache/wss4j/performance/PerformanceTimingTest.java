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
package org.apache.wss4j.performance;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.testng.annotations.*;
import org.w3c.dom.Document;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class PerformanceTimingTest extends AbstractTestBase {

    private FileWriter outSamples;

    @BeforeClass
    public void createDir() throws Exception {
        new File("target/performanceTimingTest").mkdirs();
    }

    @BeforeGroups(groups = {"timing-out"})
    public void createSampleFileOut() throws Exception {
        outSamples = new FileWriter("target/timing-out-samples.txt");
    }

    //warm up.
    @Test(groups = {"timing-out"})
    public void setUpOut() throws Exception {
        File input = genBigFile(1);
        doDOMSecurityOutbound(input, new File("target/performanceTimingTest/bigfile-dom.xml"));
        doStreamingSecurityOutbound(input, new File("target/performanceTimingTest/bigfile-stream.xml"));
    }

    @AfterGroups(groups = {"timing-out"})
    public void tearDownOut() throws Exception {
        outSamples.close();
    }

    @DataProvider(name = "xmlsizes")
    public Object[][] getXMLSizes() throws Exception {
        int tagCount = 0;
        File target = new File("target/performanceTimingTest/tmp.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new BufferedInputStream(new FileInputStream(target)));
        while (xmlStreamReader.hasNext()) {
            int eventType = xmlStreamReader.next();
            if (eventType == XMLStreamConstants.START_ELEMENT) {
                tagCount++;
            }
        }
        /*Object[][] objectArray = new Object[1][2];
        objectArray[0][0] = 4;
        objectArray[0][1] = (tagCount - 4) * 40;*/

        int size = 16;
        Object[][] objectArray = new Object[size][2];
        for (int i = 0; i < size; i++) {
            objectArray[i][0] = i + 1;
            objectArray[i][1] = (tagCount - 4) * (i + 1) * 40;
        }
        return objectArray;
    }

    @Test(groups = "timing-out", dataProvider = "xmlsizes", dependsOnMethods = "setUpOut")
    public void testOutboundTimePerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        File input = genBigFile(run * 40);
        System.gc();

        long start = System.currentTimeMillis();
        try {
            outSamples.write("" + tagCount);
            outSamples.write(" ");
            doDOMSecurityOutbound(input, new File("target/performanceTimingTest/dom-" + tagCount + ".xml"));
            outSamples.write("" + (System.currentTimeMillis() - start) / 1000.0);
        } catch (OutOfMemoryError e) {
            System.gc();
            outSamples.write("" + 0);
        }
        outSamples.write(" ");
        outSamples.flush();
        System.gc();
        System.gc();

        start = System.currentTimeMillis();
        doStreamingSecurityOutbound(input, new File("target/performanceTimingTest/stream-" + tagCount + ".xml"));
        outSamples.write("" + (System.currentTimeMillis() - start) / 1000.0);
        outSamples.write(" ");
        outSamples.flush();
        System.gc();
        System.gc();

        start = System.currentTimeMillis();
        doStreamingSecurityOutboundCompressed(input, new File("target/performanceTimingTest/stream-compressed-" + tagCount + ".xml"), "http://www.apache.org/2012/04/xmlsec/gzip");
        outSamples.write("" + (System.currentTimeMillis() - start) / 1000.0);
        outSamples.write("\n");
        outSamples.flush();
        System.gc();
        System.gc();
    }

    private FileWriter inSamples;

    @BeforeGroups(groups = {"timing-in"})
    public void createSampleFileIn() throws Exception {
        inSamples = new FileWriter("target/timing-in-samples.txt");
    }

    //warm up.
    @Test(groups = {"timing-in"}, dependsOnMethods = "testOutboundTimePerformance")
    public void setUpIn() throws Exception {
        File input = genBigFile(1);
        doDOMSecurityOutbound(input, new File("target/performanceTimingTest/bigfile-dom.xml"));
        doStreamingSecurityOutbound(input, new File("target/performanceTimingTest/bigfile-stream.xml"));
    }

    @AfterGroups(groups = {"timing-in"})
    public void tearDownIn() throws Exception {
        inSamples.close();
    }

    @Test(groups = "timing-in", dataProvider = "xmlsizes", dependsOnMethods = "setUpIn")
    public void testInboundTimePerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        System.gc();
        System.gc();

        long start = System.currentTimeMillis();
        try {
            inSamples.write("" + tagCount);
            inSamples.write(" ");
            doDOMInSecurity(new File("target/performanceTimingTest/dom-" + tagCount + ".xml"));
            inSamples.write("" + (System.currentTimeMillis() - start) / 1000.0);
        } catch (OutOfMemoryError e) {
            System.gc();
            inSamples.write("" + 0);
        }
        inSamples.write(" ");
        inSamples.flush();
        System.gc();
        System.gc();

        start = System.currentTimeMillis();
        doStreamingInSecurity(new File("target/performanceTimingTest/stream-" + tagCount + ".xml"));
        inSamples.write("" + (System.currentTimeMillis() - start) / 1000.0);
        inSamples.write(" ");
        inSamples.flush();
        System.gc();
        System.gc();

        start = System.currentTimeMillis();
        doStreamingInSecurity(new File("target/performanceTimingTest/stream-compressed-" + tagCount + ".xml"));
        inSamples.write("" + (System.currentTimeMillis() - start) / 1000.0);
        inSamples.write("\n");
        inSamples.flush();
        System.gc();
        System.gc();
    }

    private OutboundWSSec outboundWSSec;

    private void doStreamingSecurityOutbound(File source, File output) throws Exception {
        if (outboundWSSec == null) {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            securityProperties.setActions(actions);
            securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)
            outboundWSSec = WSSec.getOutboundWSSec(securityProperties);
        }

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream(source));
        XMLStreamWriter xmlStreamWriter = outboundWSSec.processOutMessage(new BufferedOutputStream(new FileOutputStream(output)), "UTF-8", new ArrayList<>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        xmlStreamReader.close();
    }

    private OutboundWSSec outboundWSSecCompressed;

    private void doStreamingSecurityOutboundCompressed(File source, File output, String compress) throws Exception {
        if (outboundWSSecCompressed == null) {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            securityProperties.setActions(actions);
            securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)
            securityProperties.setEncryptionCompressionAlgorithm(compress);
            outboundWSSecCompressed = WSSec.getOutboundWSSec(securityProperties);
        }

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream(source));
        XMLStreamWriter xmlStreamWriter = outboundWSSecCompressed.processOutMessage(new BufferedOutputStream(new FileOutputStream(output)), "UTF-8", new ArrayList<>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        xmlStreamReader.close();
    }

    private void doDOMSecurityOutbound(File input, File output) throws WSSecurityException, FileNotFoundException, TransformerException {
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setProperty(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
        properties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "" + 60 * 60 * 24 * 7);
        Document doc = doOutboundSecurityWithWSS4J(new FileInputStream(input), WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT, properties);
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(output));
    }

    private File genBigFile(int factor) throws IOException {
        File target = new File("target/performanceTimingTest/tmp.xml");
        FileWriter fileWriter = new FileWriter(target, false);
        fileWriter.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "<env:Header></env:Header>\n" +
                "<env:Body><test xmlns=\"http://www.example.com\">");
        fileWriter.close();
        FileOutputStream fileOutputStream = new FileOutputStream(target, true);
        for (int i = 0; i < factor; i++) {
            int read = 0;
            byte[] buffer = new byte[4096];
            InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            while ((read = inputStream.read(buffer)) != -1) {
                fileOutputStream.write(buffer, 0, read);
            }
            inputStream.close();
        }
        fileOutputStream.close();
        fileWriter = new FileWriter(target, true);
        fileWriter.write("</test></env:Body>\n" +
                "</env:Envelope>");
        fileWriter.close();

        return target;
    }

    private void doDOMInSecurity(File input) throws Exception {
        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "" + 60 * 60 * 24 * 7);
        doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(input), action, properties, false);
    }

    private InboundWSSec inboundWSSec;

    private void doStreamingInSecurity(File input) throws Exception {
        if (inboundWSSec == null) {
            WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
            inSecurityProperties.setStrictTimestampCheck(false);
            inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());

            inboundWSSec = WSSec.getInboundWSSec(inSecurityProperties);
        }
        InputStream fileInputStream = new BufferedInputStream(new FileInputStream(input));
        XMLStreamReader outXmlStreamReader = inboundWSSec.processInMessage(xmlInputFactory.createXMLStreamReader(fileInputStream));

        while (outXmlStreamReader.hasNext()) {
            outXmlStreamReader.next();
        }
        fileInputStream.close();
        outXmlStreamReader.close();
    }
}
