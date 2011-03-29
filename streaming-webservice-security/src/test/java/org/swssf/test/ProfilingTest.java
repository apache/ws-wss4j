/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.swssf.test;

import org.swssf.WSSec;
import org.swssf.ext.InboundWSSec;
import org.swssf.ext.SecurityProperties;
import org.swssf.test.utils.XmlReaderToWriter;
import org.testng.annotations.Test;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * @author giger
 */
public class ProfilingTest extends AbstractTestBase {
/*
    @Test(invocationCount = 1)
    public void testWSS4JOutbound() throws Exception {
        InputStream sourceDocument = new BufferedInputStream(new FileInputStream("ICHAGCompany-3000.xml"));

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

        javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(new FileOutputStream("ICHAGCompany-3000-sig-enc.xml")));
    }
 */

    @Test(invocationCount = 1)
    public void testStreamingSecOutbound() throws Exception {
/*
        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        securityProperties.setOutAction(actions);
        securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream("ICHAGCompany-3000.xml"));
        OutboundWSSec xmlSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(new FileOutputStream("ICHAGCompany-3000-sig-enc.xml"));
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        xmlStreamReader.close();

 */
    }


/*
    @Test(invocationCount = 1)
    public void testWSS4JInbound() throws Exception {
        InputStream sourceDocument = new FileInputStream("ICHAGCompany-3000-sig-enc.xml");
        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Document document = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(sourceDocument), action);
    }
*/

    @Test(invocationCount = 1, dependsOnMethods = {"testStreamingSecOutbound"})
    public void testStreamingSecInbound() throws Exception {

        final ThreadStopper threadStopper = new ThreadStopper();
        final List<Integer> times = new ArrayList<Integer>();
        final List<Integer> memory = new ArrayList<Integer>();

        Runnable myRunnable = new Runnable() {

            public void run() {

                int sleepTime = 100;

                long currentTime = System.currentTimeMillis();

                while (!threadStopper.isStop()) {
                    try {
                        Thread.sleep(sleepTime);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                    System.gc();
                    times.add(((int) (System.currentTimeMillis() - currentTime - sleepTime)));
                    memory.add(((int) ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024)));
                    currentTime = System.currentTimeMillis();
                }
            }
        };

        Thread thread = new Thread(myRunnable);
        thread.setPriority(8);
        thread.start();

        InputStream sourceDocument = new FileInputStream("ICHAGCompany-3000-sig-enc.xml");

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setStrictTimestampCheck(false);
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader outXmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(sourceDocument));

        XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
        XmlReaderToWriter.writeAll(outXmlStreamReader, xmlOutputFactory.createXMLStreamWriter(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                //dev/null
            }
        }));

        threadStopper.setStop(true);
        thread.join();

        int minTime = Integer.MAX_VALUE;
        int averageTime = 0;
        int maxTime = Integer.MIN_VALUE;
        for (int i = 0; i < times.size(); i++) {
            int time = times.get(i);
            minTime = time < minTime ? time : minTime;
            maxTime = time > maxTime ? time : maxTime;
            averageTime += time;
        }
        System.out.println("Min gc time: " + minTime);
        System.out.println("Average gc time: " + averageTime / times.size());
        System.out.println("Max gc time: " + maxTime);

        int minMem = Integer.MAX_VALUE;
        int averageMem = 0;
        int maxMem = Integer.MIN_VALUE;
        for (int i = 0; i < memory.size(); i++) {
            int mem = memory.get(i);
            minMem = mem < minMem ? mem : minMem;
            maxMem = mem > maxMem ? mem : maxMem;
            averageMem += mem;
        }
        System.out.println("Min memory usage: " + minMem + "MB");
        System.out.println("Average memory usage: " + averageMem / memory.size() + "MB");
        System.out.println("Max memory usage: " + maxMem + "MB");
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


/*
   @Test(invocationCount = 1)
   public void testStreamingSecOutbound() throws Exception {
       SecurityProperties securityProperties = new SecurityProperties();
       securityProperties.setCallbackHandler(new CallbackHandlerImpl());
       securityProperties.setEncryptionUser("receiver");
       securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
       securityProperties.setSignatureUser("transmitter");
       securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
       Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
       securityProperties.setOutAction(actions);
       securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)

       InputStream sourceDocument = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
       OutboundWSSec xmlSecOut = WSSec.getOutboundWSSec(securityProperties);
       XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(new FileOutputStream("plain-soap-sig-enc.xml"));
       XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
       XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
       xmlStreamWriter.close();
       xmlStreamReader.close();
   }

   @Test(invocationCount = 1, dependsOnMethods = {"testStreamingSecOutbound"})
   public void testStreamingSecInbound() throws Exception {

       InputStream sourceDocument = new FileInputStream("plain-soap-sig-enc.xml");

       SecurityProperties securityProperties = new SecurityProperties();
       securityProperties.setCallbackHandler(new CallbackHandlerImpl());
       securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
       securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

       InboundWSSec xmlSec = WSSec.getInboundWSSec(securityProperties);
       XMLStreamReader outXmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(sourceDocument));

       XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
       XmlReaderToWriter.writeAll(outXmlStreamReader, xmlOutputFactory.createXMLStreamWriter(new OutputStream() {
           @Override
           public void write(int b) throws IOException {
               //dev/null
           }
       }));
   }
*/
}
