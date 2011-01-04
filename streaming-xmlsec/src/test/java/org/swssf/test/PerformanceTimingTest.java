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
import org.swssf.ext.Constants;
import org.swssf.ext.OutboundXMLSec;
import org.swssf.ext.SecurePart;
import org.swssf.ext.SecurityProperties;
import org.swssf.test.utils.XmlReaderToWriter;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.Properties;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class PerformanceTimingTest extends AbstractTestBase {

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
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.addEncryptionPart(new SecurePart("test", "http://www.example.com", "Content"));
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
        securityProperties.setOutAction(actions);
        securityProperties.setTimestampTTL(60 * 60 * 24 * 7); //a week for testing:)

        InputStream sourceDocument = new BufferedInputStream(new FileInputStream(source));
        OutboundXMLSec xmlSecOut = WSSec.getOutboundXMLSec(securityProperties);

        XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(new FileOutputStream(output));
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

    @Test(groups = { "timing", "policy" })
    public void setUp() throws Exception {
        File input = prepareBigEncryptedFile(1);
        doDOMInSecurity(input, false);
        doStreamingInSecurity(input, false);
    }

    @Test(groups = "timing")
    public void testStreamingTimePerformance() throws Exception {

        FileWriter samples = new FileWriter("timing-samples.txt");

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);
            File input = prepareBigEncryptedFile(i * 10);

            long start = System.currentTimeMillis();

            int tagCount = doStreamingInSecurity(input, false);

            samples.write("" + tagCount);
            samples.write(" ");
            samples.write("" + (System.currentTimeMillis() - start) / 1000.0);
            samples.write(" ");
            samples.flush();

            System.out.println("Stream Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCount);
            System.out.println("");
	        System.gc();

            start = System.currentTimeMillis();

            tagCount = doDOMInSecurity(input, true);

            samples.write("" + (System.currentTimeMillis() - start) / 1000.0);
            samples.write("\n");
            samples.flush();

            System.out.println("DOM Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCount);
            System.out.println("");
            System.gc();
            System.out.println("Used memory: " + ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024));
        }

        samples.close();
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

    @Test(groups = "timing-out")
    public void testStreamingOutTimePerformance() throws Exception {

        FileWriter samples = new FileWriter("timing-out-samples.txt");

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);
            File input = genBigFile(i * 10);

            long start = System.currentTimeMillis();

            doStreamingSecurityOutbound(input, new File("target/bigfile-stream.xml"));

            samples.write("" + tagCounts[i - 1]);
            samples.write(" ");
            samples.write("" + (System.currentTimeMillis() - start) / 1000.0);
            samples.write(" ");
            samples.flush();

            System.out.println("Stream Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCounts[i - 1]);
            System.out.println("");
            System.gc();

            start = System.currentTimeMillis();

            Document doc = doOutboundSecurityWithWSS4J(new FileInputStream(input), WSHandlerConstants.ENCRYPT, new Properties());
            javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(new File("target/bigfile-dom.xml")));

            samples.write("" + (System.currentTimeMillis() - start) / 1000.0);
            samples.write("\n");
            samples.flush();

            System.out.println("DOM Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCounts[i - 1]);
            System.out.println("");
            System.gc();
            System.out.println("Used memory: " + ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024));
        }

        samples.close();
    }
/*
    @Test(groups = "policy")
    public void testPolicyTimePerformance() throws Exception {

        FileWriter samples = new FileWriter("policy-timing-samples.txt");

        for (int i = 1; i <= 15; i++) {
            System.out.println("Run " + i);
            File input = prepareBigEncryptedFile(i * 10);

            long start = System.currentTimeMillis();

            int tagCount = doStreamingInSecurity(input, true);

            samples.write("" + tagCount);
            samples.write(" ");
            samples.write("" + (System.currentTimeMillis() - start) / 1000.0);
            samples.write(" ");
            samples.flush();

            System.out.println("Stream Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCount);
            System.out.println("");
	        System.gc();

            start = System.currentTimeMillis();

            tagCount = doDOMInSecurity(input, true);

            samples.write("" + (System.currentTimeMillis() - start) / 1000.0);
            samples.write("\n");
            samples.flush();

            System.out.println("DOM Time: " + (System.currentTimeMillis() - start) / 1000.0 + "s");
            System.out.println("Tag Count: " + tagCount);
            System.out.println("");
            System.gc();
            System.out.println("Used memory: " + ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024));
        }

        samples.close();
    }

    private int doDOMInSecurity(File input, boolean doPolicy) throws Exception {
        int tagCount;
        String action = WSHandlerConstants.ENCRYPT;

        XMLStreamReader xmlStreamReader = null;
        if (doPolicy) {
            MessageContext messageContext = doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(input), action);
            System.out.println(messageContext);

            Vector<WSHandlerResult> recv_results = (Vector<WSHandlerResult>)messageContext.getProperty(WSHandlerConstants.RECV_RESULTS);
            for (int i = 0; i < recv_results.size(); i++) {
                WSHandlerResult wsHandlerResult = recv_results.get(i);
                Vector<WSSecurityEngineResult> wsSecurityEngineResults = wsHandlerResult.getResults();
                for (int j = 0; j < wsSecurityEngineResults.size(); j++) {
                    WSSecurityEngineResult wsSecurityEngineResult = wsSecurityEngineResults.get(j);
                    if (((Integer)wsSecurityEngineResult.get(WSSecurityEngineResult.TAG_ACTION)) == WSConstants.ENCR) {
                        List<WSDataRef> dataRefUris = (List<WSDataRef>)wsSecurityEngineResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                        //this is not correct but works for measuring
                        if (!dataRefUris.get(0).getName().equals(Constants.TAG_soap11_Body)) {
                            return 0;
                        }
                    }
                }
            }

        } else {
            Document document = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(input), action);
            xmlStreamReader = new W3CDOMStreamReader(document.getDocumentElement());
        }

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

    private int doStreamingInSecurity(File input, boolean doPolicy) throws Exception {
        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());

        PolicyEnforcer policyEnforcer = null;
        if (doPolicy) {
            System.out.println("Added policy");
            PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(new File("policyPerformance.wsdl").toURI().toURL());
            policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
            inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));
        }
        InboundXMLSec xmlSec = WSSec.getInboundXMLSec(inSecurityProperties);
        FileInputStream fileInputStream = new FileInputStream(input);
        XMLStreamReader outXmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(fileInputStream), policyEnforcer);

        int tagCount = 0;

        try {
            while (outXmlStreamReader.hasNext()) {
                int eventType = outXmlStreamReader.next();
                if (eventType == XMLStreamConstants.START_ELEMENT) {
                    tagCount++;
                }
            }
            fileInputStream.close();
            outXmlStreamReader.close();
        } catch (XMLStreamException e) {
            if (e.getCause() instanceof WSSPolicyException) {
                //ignore
            } else {
                throw e;
            }            
        }
        return tagCount;
    }
    */
}
