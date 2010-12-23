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
package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.ext.Constants;
import ch.gigerstyle.xmlsec.ext.SecurityProperties;
import ch.gigerstyle.xmlsec.test.utils.CustomW3CDOMStreamReader;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import java.io.*;
import java.util.Properties;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class InteroperabilityTest extends AbstractTestBase {

    @Test(invocationCount = 1)
    public void testInteroperabilityInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());

        Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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

    @Test(invocationCount = 1)
    public void testInteroperabilityInboundReverseOrder() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

        String action = WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());

        Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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

    @Test
    public void testInteroperabilityOutbound() throws Exception {

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        securityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Document document = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
    }

    @Test
    public void testInteroperabilityOutboundReverseOrder() throws Exception {

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT, Constants.Action.SIGNATURE, Constants.Action.TIMESTAMP};
        securityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
        Document document = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
    }

    @Test
    public void testInteroperabilityOutboundSignature() throws Exception {

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
        securityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.SIGNATURE;
        Document document = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
    }

    @Test(invocationCount = 1)
    public void testInteroperabilityInboundSecurityHeaderTimestampOrder() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Content}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedData");
        Element timeStamp = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        Element securityHeaderNode = (Element) timeStamp.getParentNode();
        securityHeaderNode.removeChild(timeStamp);

        xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature");
        Element signature = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);

        securityHeaderNode.insertBefore(timeStamp, signature);

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        //transformer.transform(new DOMSource(securedDocument), new StreamResult(System.out));

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());

        Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

        //read the whole stream:
        //Transformer transformer = TransformerFactory.newInstance().newTransformer();
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
