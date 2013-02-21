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
package org.apache.wss4j.stax.test;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
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
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PerformanceMemoryTest extends AbstractTestBase {

    private FileWriter outSamples;

    @BeforeClass
    public void createDir() throws Exception {
        new File("target/performanceMemoryTest").mkdirs();
    }

    @BeforeGroups(groups = {"memory-out"})
    public void createSampleFileOut() throws Exception {
        outSamples = new FileWriter("target/memory-out-samples.txt");
    }

    //warm up.
    @BeforeMethod(groups = {"memory-out"})
    public void setUpOut() throws Exception {
        File input = genBigFile(1);
        doDOMSecurityOutbound(input, new File("target/performanceMemoryTest/bigfile-dom.xml"));
        doStreamingSecurityOutbound(input, new File("target/performanceMemoryTest/bigfile-stream.xml"));
    }

    @AfterGroups(groups = {"memory-out"})
    public void tearDownOut() throws Exception {
        outSamples.close();
    }

    @DataProvider(name = "xmlsizes")
    public Object[][] getXMLSizes() throws Exception {
        File input = genBigFile(1);
        int tagCount = 0;
        File target = new File("target/performanceMemoryTest/tmp.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new BufferedInputStream(new FileInputStream(target)));
        while (xmlStreamReader.hasNext()) {
            int eventType = xmlStreamReader.next();
            if (eventType == XMLStreamConstants.START_ELEMENT) {
                tagCount++;
            }
        }
        /*Object[][] objectArray = new Object[1][2];
        objectArray[0][0] = 10;
        objectArray[0][1] = (tagCount - 4) * 10;*/

        int size = 16;
        Object[][] objectArray = new Object[size][2];
        for (int i = 0; i < size; i++) {
            objectArray[i][0] = i + 1;
            objectArray[i][1] = (tagCount - 4) * (i + 1) * 40;
        }
        return objectArray;
    }

    @BeforeGroups(groups = {"memory-out"}, dependsOnMethods = {"createSampleFileOut"})
    public void printTagCountsOut() throws Exception {
        Object[][] sizes = getXMLSizes();
        for (int i = 0; i < sizes.length; i++) {
            Object[] size = sizes[i];
            outSamples.write("" + size[1] + " ");
        }
    }


    @Test(groups = "memory-out", dataProvider = "xmlsizes", dependsOnMethods = {"doBeforeStreamOut"})
    public void testOutStreamingMemoryPerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        File input = genBigFile(run * 40);
        long startMem = getUsedMemory();

        ThreadStopper threadStopper = new ThreadStopper();
        Thread thread = new Thread(new MemorySamplerThread(threadStopper, outSamples, startMem));
        thread.setPriority(9);
        thread.start();

        doStreamingSecurityOutbound(input, new File("target/performanceMemoryTest/stream-" + tagCount + ".xml"));

        threadStopper.setStop(true);
        thread.join();
    }

    @Test(groups = "memory-out", dataProvider = "xmlsizes", dependsOnMethods = {"doBeforeStreamCompressedOut"})
    public void testOutStreamingCompressedMemoryPerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        File input = genBigFile(run * 40);
        long startMem = getUsedMemory();

        ThreadStopper threadStopper = new ThreadStopper();
        Thread thread = new Thread(new MemorySamplerThread(threadStopper, outSamples, startMem));
        thread.setPriority(9);
        thread.start();

        doStreamingSecurityOutboundCompressed(input, new File("target/performanceMemoryTest/stream-compressed-" + tagCount + ".xml"), "http://www.apache.org/2012/04/xmlsec/gzip");

        threadStopper.setStop(true);
        thread.join();
    }

    @Test(groups = "memory-out", dataProvider = "xmlsizes", dependsOnMethods = {"doBeforeDOMOut"})
    public void testOutDOMMemoryPerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        File input = genBigFile(run * 40);
        long startMem = getUsedMemory();

        ThreadStopper threadStopper = new ThreadStopper();
        Thread thread = new Thread(new MemorySamplerThread(threadStopper, outSamples, startMem));
        thread.setPriority(9);
        thread.start();

        doDOMSecurityOutbound(input, new File("target/performanceMemoryTest/dom-" + tagCount + ".xml"));

        threadStopper.setStop(true);
        thread.join();
    }

    @Test(groups = {"memory-out"})
    public void doBeforeDOMOut() throws Exception {
        outSamples.write("\n");
    }

    @Test(groups = {"memory-out"})
    public void doBeforeStreamOut() throws Exception {
        outSamples.write("\n");
    }

    @Test(groups = {"memory-out"})
    public void doBeforeStreamCompressedOut() throws Exception {
        outSamples.write("\n");
    }

    @Test(groups = {"memory-in"})
    public void doBeforeDOMIn() throws Exception {
        inSamples.write("\n");
    }

    @Test(groups = {"memory-in"})
    public void doBeforeStreamIn() throws Exception {
        inSamples.write("\n");
    }

    @Test(groups = {"memory-in"})
    public void doBeforeStreamCompressedIn() throws Exception {
        inSamples.write("\n");
    }

    private FileWriter inSamples;

    @BeforeGroups(groups = {"memory-in"})
    public void createSampleFileIn() throws Exception {
        inSamples = new FileWriter("target/memory-in-samples.txt");
    }

    //warm up.
    @BeforeMethod(groups = {"memory-in"}, dependsOnGroups = {"memory-out"})
    public void setUpIn() throws Exception {
        File input = genBigFile(1);
        doDOMInSecurity(new File("target/performanceMemoryTest/bigfile-dom.xml"));
        doStreamingInSecurity(new File("target/performanceMemoryTest/bigfile-stream.xml"));
    }

    @AfterGroups(groups = {"memory-in"})
    public void tearDownIn() throws Exception {
        inSamples.close();
    }

    @BeforeGroups(groups = {"memory-in"}, dependsOnMethods = {"createSampleFileIn"})
    public void printTagCountsIn() throws Exception {
        Object[][] sizes = getXMLSizes();
        for (int i = 0; i < sizes.length; i++) {
            Object[] size = sizes[i];
            inSamples.write("" + size[1] + " ");
        }
    }


    @Test(groups = "memory-in", dataProvider = "xmlsizes", dependsOnMethods = {"doBeforeStreamIn", "testOutStreamingMemoryPerformance"})
    public void testInboundStreamingMemoryPerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        long startMem = getUsedMemory();

        ThreadStopper threadStopper = new ThreadStopper();
        Thread thread = new Thread(new MemorySamplerThread(threadStopper, inSamples, startMem));
        thread.setPriority(9);
        thread.start();

        doStreamingInSecurity(new File("target/performanceMemoryTest/stream-" + tagCount + ".xml"));

        threadStopper.setStop(true);
        thread.join();
    }

    @Test(groups = "memory-in", dataProvider = "xmlsizes", dependsOnMethods = {"doBeforeStreamCompressedIn", "testOutStreamingCompressedMemoryPerformance"})
    public void testInboundStreamingCompressedMemoryPerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        long startMem = getUsedMemory();

        ThreadStopper threadStopper = new ThreadStopper();
        Thread thread = new Thread(new MemorySamplerThread(threadStopper, inSamples, startMem));
        thread.setPriority(9);
        thread.start();

        doStreamingInSecurity(new File("target/performanceMemoryTest/stream-compressed-" + tagCount + ".xml"));

        threadStopper.setStop(true);
        thread.join();
    }

    @Test(groups = "memory-in", dataProvider = "xmlsizes", dependsOnMethods = {"doBeforeDOMIn", "testOutDOMMemoryPerformance"})
    public void testInboundDOMMemoryPerformance(int run, int tagCount) throws Exception {

        System.out.println("Run " + run);
        long startMem = getUsedMemory();

        ThreadStopper threadStopper = new ThreadStopper();
        Thread thread = new Thread(new MemorySamplerThread(threadStopper, inSamples, startMem));
        thread.setPriority(9);
        thread.start();

        doDOMInSecurity(new File("target/performanceMemoryTest/dom-" + tagCount + ".xml"));

        threadStopper.setStop(true);
        thread.join();
    }


    private OutboundWSSec outboundWSSec = null;

    private void doStreamingSecurityOutbound(File source, File output) throws Exception {
        if (outboundWSSec == null) {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)
            outboundWSSec = WSSec.getOutboundWSSec(securityProperties);
        }

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream(source));
        XMLStreamWriter xmlStreamWriter = outboundWSSec.processOutMessage(new BufferedOutputStream(new FileOutputStream(output)), "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        xmlStreamReader.close();
    }

    private OutboundWSSec outboundWSSecCompressed = null;

    private void doStreamingSecurityOutboundCompressed(File source, File output, String compress) throws Exception {
        if (outboundWSSecCompressed == null) {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)
            securityProperties.setEncryptionCompressionAlgorithm(compress);
            outboundWSSecCompressed = WSSec.getOutboundWSSec(securityProperties);
        }

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream(source));
        XMLStreamWriter xmlStreamWriter = outboundWSSecCompressed.processOutMessage(new BufferedOutputStream(new FileOutputStream(output)), "UTF-8", new ArrayList<SecurityEvent>());
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
        File target = new File("target/performanceMemoryTest/tmp.xml");
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

    private InboundWSSec inboundWSSec = null;

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


    private static void gc() {
        System.gc();
        System.runFinalization();
        System.gc();
    }


    private static long getUsedMemory() {
        gc();
        gc();
        long totalMemory = Runtime.getRuntime().totalMemory();
        long freeMemory = Runtime.getRuntime().freeMemory();
        return totalMemory - freeMemory;
    }

    class ThreadStopper {
        private volatile boolean stop = false;

        public boolean isStop() {
            return stop;
        }

        public void setStop(boolean stop) {
            this.stop = stop;
        }
    }

    class MemorySamplerThread implements Runnable {

        private ThreadStopper threadStopper;
        private FileWriter fileWriter;
        private long memoryDiff = 0;
        private Thread parentThread;

        private List<Integer> memory = new LinkedList<Integer>();

        MemorySamplerThread(ThreadStopper threadStopper, FileWriter fileWriter, long memoryDiff) {
            this.threadStopper = threadStopper;
            this.fileWriter = fileWriter;
            this.memoryDiff = memoryDiff;
            this.parentThread = Thread.currentThread();
        }

        @Override
        public void run() {

            int sleepTime = 100;

            while (!threadStopper.isStop()) {
                try {
                    Thread.sleep(sleepTime);
                    if (threadStopper.isStop()) {
                        break;
                    }
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                //parentThread.suspend();
                memory.add((int) (((getUsedMemory()) - memoryDiff) / 1024.0 / 1024.0));
                //System.out.println("Sample: " + memory.get(memory.size() - 1));
                //parentThread.resume();
            }

            System.out.println("Collected " + memory.size() + " samples");

            int maxMem = Integer.MIN_VALUE;
            for (int i = 0; i < memory.size(); i++) {
                //System.out.println("Sample: " + memory.get(i));
                int mem = memory.get(i);
                maxMem = mem > maxMem ? mem : maxMem;
            }

            try {
                fileWriter.write("" + maxMem + " ");
                fileWriter.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            System.out.println("Max memory usage: " + maxMem + "MB");
        }
    }
}
