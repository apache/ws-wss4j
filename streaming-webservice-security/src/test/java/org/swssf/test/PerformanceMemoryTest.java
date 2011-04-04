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

import org.apache.cxf.staxutils.W3CDOMStreamReader;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.WSSec;
import org.swssf.ext.Constants;
import org.swssf.ext.InboundWSSec;
import org.swssf.ext.OutboundWSSec;
import org.swssf.ext.SecurityProperties;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.test.utils.XmlReaderToWriter;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class PerformanceMemoryTest extends AbstractTestBase {

    private File prepareBigEncryptedFile(int factor) throws Exception {
        File target = genBigFile(factor);
        File output = new File("target/enc.xml");
        doStreamingSecurityOutbound(target, output);
        return output;
    }

    private void doStreamingSecurityOutbound(File source, File output) throws Exception {
        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
        securityProperties.setOutAction(actions);
        securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream(source));
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(new FileOutputStream(output), "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        xmlStreamReader.close();
    }

    private File genBigFile(int factor) throws IOException {
        File source = new File("ReferenzInstanzdokument20060922.xml");
        File target = new File("target/tmp.xml");
        FileWriter fileWriter = new FileWriter(target);
        fileWriter.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "<env:Header></env:Header>\n" +
                "<env:Body><test xmlns=\"http://www.example.com\">");
        fileWriter.close();
        FileOutputStream fileOutputStream = new FileOutputStream(target, true);
        for (int i = 0; i <= factor; i++) {
            int read = 0;
            byte[] buffer = new byte[4096];
            FileInputStream fileInputStream = new FileInputStream(source);
            while ((read = fileInputStream.read(buffer)) != -1) {
                fileOutputStream.write(buffer, 0, read);
            }
            fileInputStream.close();
        }
        fileWriter = new FileWriter(target, true);
        fileWriter.write("</test></env:Body>\n" +
                "</env:Envelope>");
        fileWriter.close();
        return target;
    }

    /*
    private int countTags(File file) throws Exception {
        int tagCount = 0;
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new FileInputStream(file));
        while (xmlStreamReader.hasNext()) {
            int eventType = xmlStreamReader.next();
            if (eventType == XMLStreamConstants.START_ELEMENT) {
                tagCount++;
            }
        }
        return tagCount;
    }
    */

    private int[] tagCounts = new int[]{33391, 63731, 94071, 124411, 154751, 185091, 215431, 245771, 276111, 306451, 336791, 367131, 397471, 427811, 458151};

    @Test(groups = {"timing-out"})
    public void setUpOut() throws Exception {
        File input = genBigFile(1);
        Document doc = doOutboundSecurityWithWSS4J(new FileInputStream(input), WSHandlerConstants.ENCRYPT, new Properties());
        javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(new File("target/bigfile-dom.xml")));
        doStreamingSecurityOutbound(input, new File("target/bigfile-stream.xml"));
    }

    @Test(groups = "streaming-memory-out")
    public void testStreamingOutMemoryPerformance() throws Exception {

        FileWriter samples = new FileWriter("memory-samples-stream-out.txt");
        long memoryDiff = 0;

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);

            long startMem = getUsedMemory();
            System.out.println("Start Mem: " + startMem / 1024.0 / 1024.0);

            File input = genBigFile(i * 10);

            ThreadStopper threadStopper = new ThreadStopper();
            Thread thread = new Thread(new MemorySamplerThread(threadStopper, samples, memoryDiff));
            thread.setPriority(8);
            thread.start();

            long start = System.currentTimeMillis();
            doStreamingSecurityOutbound(input, new File("target/bigfile-stream.xml"));

            samples.write("" + tagCounts[i - 1]);
            samples.write(" ");
            samples.flush();

            threadStopper.setStop(true);

            System.out.println("Stream Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCounts[i - 1]);
            System.out.println("");

            thread.join();

            samples.write("\n");
            samples.flush();
            long endMem = getUsedMemory();
            memoryDiff = endMem - startMem;
            System.out.println("Memory leak: " + ((memoryDiff)) / 1024.0 / 1024.0);
            System.out.println("Used memory: " + (endMem / 1024.0 / 1024.0));
            System.out.println("");
        }

        samples.close();
    }

    @Test(groups = "dom-memory-out")
    public void testDOMOutMemoryPerformance() throws Exception {

        FileWriter samples = new FileWriter("memory-samples-dom-out.txt");
        long memoryDiff = 0;
        long leakedMemory = 0;

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);

            long startMem = getUsedMemory();
            System.out.println("Start Mem: " + startMem / 1024.0 / 1024.0);

            File input = genBigFile(i * 10);

            ThreadStopper threadStopper = new ThreadStopper();
            Thread thread = new Thread(new MemorySamplerThread(threadStopper, samples, leakedMemory));
            thread.setPriority(8);
            thread.start();

            long start = System.currentTimeMillis();

            Document doc = doOutboundSecurityWithWSS4J(new FileInputStream(input), WSHandlerConstants.ENCRYPT, new Properties());
            javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(new File("target/bigfile-dom.xml")));

            samples.write("" + tagCounts[i - 1]);
            samples.write(" ");
            samples.flush();

            threadStopper.setStop(true);

            System.out.println("DOM Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCounts[i - 1]);
            System.out.println("");

            thread.join();

            samples.write("\n");
            samples.flush();
            long endMem = getUsedMemory();
            memoryDiff = endMem - startMem;
            leakedMemory += memoryDiff;
            System.out.println("Memory leak: " + ((memoryDiff)) / 1024.0 / 1024.0);
            System.out.println("Used memory: " + (endMem / 1024.0 / 1024.0));
            System.out.println("");
        }

        samples.close();
    }

    @Test(groups = "stream")
    public void testStreamingMemoryPerformance() throws Exception {

        FileWriter samples = new FileWriter("memory-samples-stream.txt");
        long memoryDiff = 0;

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);

            long startMem = getUsedMemory();
            System.out.println("Start Mem: " + startMem / 1024.0 / 1024.0);

            File input = prepareBigEncryptedFile(i * 10);

            ThreadStopper threadStopper = new ThreadStopper();
            Thread thread = new Thread(new MemorySamplerThread(threadStopper, samples, memoryDiff));
            thread.setPriority(8);
            thread.start();

            long start = System.currentTimeMillis();
            int tagCount = doStreamingInSecurity(input);

            samples.write("" + tagCount);
            samples.write(" ");
            samples.flush();

            threadStopper.setStop(true);

            System.out.println("Stream Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCount);
            System.out.println("");

            thread.join();

            samples.write("\n");
            samples.flush();
            long endMem = getUsedMemory();
            memoryDiff = endMem - startMem;
            System.out.println("Memory leak: " + ((memoryDiff)) / 1024.0 / 1024.0);
            System.out.println("Used memory: " + (endMem / 1024.0 / 1024.0));
            System.out.println("");
        }

        samples.close();
    }

    private static void gc() {
        /*
        try {
            System.gc();
            Thread.sleep(100);
            System.runFinalization();
            Thread.sleep(100);
            System.gc();
            Thread.sleep(100);
            System.runFinalization();
            Thread.sleep(100);
        } catch (Exception e) {
            e.printStackTrace();
        }
        */
        System.gc();
        System.runFinalization();
        System.gc();
    }


    private static long getUsedMemory() {
        gc();
        long totalMemory = Runtime.getRuntime().totalMemory();
        gc();
        long freeMemory = Runtime.getRuntime().freeMemory();
        long usedMemory = totalMemory - freeMemory;
        return usedMemory;

    }

    @Test(groups = "dom")
    public void testDOMMemoryPerformance() throws Exception {

        FileWriter samples = new FileWriter("memory-samples-dom.txt");
        long memoryDiff = 0;
        long leakedMemory = 0;

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);

            long startMem = getUsedMemory();
            System.out.println("Start Mem: " + startMem / 1024.0 / 1024.0);

            File input = prepareBigEncryptedFile(i * 10);

            ThreadStopper threadStopper = new ThreadStopper();
            Thread thread = new Thread(new MemorySamplerThread(threadStopper, samples, leakedMemory));
            thread.setPriority(8);
            thread.start();

            long start = System.currentTimeMillis();
            int tagCount = doDOMInSecurity(input);

            samples.write("" + tagCount);
            samples.write(" ");
            samples.flush();

            threadStopper.setStop(true);

            System.out.println("DOM Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCount);
            System.out.println("");

            thread.join();

            samples.write("\n");
            samples.flush();
            long endMem = getUsedMemory();
            memoryDiff = endMem - startMem;
            leakedMemory += memoryDiff;
            System.out.println("Memory leak: " + ((memoryDiff)) / 1024.0 / 1024.0);
            System.out.println("Used memory: " + (endMem / 1024.0 / 1024.0));
            System.out.println("");
        }

        samples.close();
    }

    private int doDOMInSecurity(File input) throws Exception {
        int tagCount;
        String action = WSHandlerConstants.ENCRYPT;
        Document document = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(input), action);
        XMLStreamReader xmlStreamReader = new W3CDOMStreamReader(document.getDocumentElement());

        tagCount = 0;
        while (xmlStreamReader.hasNext()) {
            int eventType = xmlStreamReader.next();
            if (eventType == XMLStreamConstants.START_ELEMENT) {
                tagCount++;
            }
        }

        xmlStreamReader.close();
        return tagCount;
    }

    private int doStreamingInSecurity(File input) throws Exception {
        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());

        InboundWSSec wsSecIn = WSSec.getInboundWSSec(inSecurityProperties);
        FileInputStream fileInputStream = new FileInputStream(input);
        XMLStreamReader outXmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(fileInputStream));

        int tagCount = 0;
        while (outXmlStreamReader.hasNext()) {
            int eventType = outXmlStreamReader.next();
            if (eventType == XMLStreamConstants.START_ELEMENT) {
                tagCount++;
            }
        }
        fileInputStream.close();
        outXmlStreamReader.close();
        return tagCount;
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
                fileWriter.write("" + maxMem);
                fileWriter.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            System.out.println("Max memory usage: " + maxMem + "MB");
        }
    }
}
