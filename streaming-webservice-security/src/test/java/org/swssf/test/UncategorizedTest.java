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

import org.swssf.config.Init;
import org.swssf.ext.WSSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.net.URL;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class UncategorizedTest extends AbstractTestBase {

    @Test
    public void testConfigurationLoadFromUrl() throws Exception {
        URL url = this.getClass().getClassLoader().getResource("testdata/plain-soap-1.1.xml");
        try {
            Init.init(url);
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "General security error; nested exception is: \n" +
                    "\tjavax.xml.bind.UnmarshalException\n" +
                    " - with linked exception:\n" +
                    "[org.xml.sax.SAXParseException: cvc-elt.1: Cannot find the declaration of element 'env:Envelope'.]");
        }
    }

    /*@Test(invocationCount = 1)
    public void testRandomInput() throws Exception {

        String[] schemas = new String[4];
        schemas[0] = "src/main/resources/schemas/xenc-schema.xsd";
        schemas[1] = "src/main/resources/schemas/xmldsig-core-schema.xsd";
        schemas[2] = "src/main/resources/schemas/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        schemas[3] = "src/main/resources/schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        XMLGen xmlGen = new XMLGen(schemas);

        javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

         org.w3c.dom.Document w3cDoc = null;

        Result streamResult = new StreamResult(new FileOutputStream("xml.out", true));

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());

        while (true) {
            try {
                Document doc = xmlGen.getRandom("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security");

                w3cDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();

                transformer.transform(new DocumentSource(doc), new DOMResult(w3cDoc));

                Element envelope = w3cDoc.createElementNS(Constants.NS_SOAP11, Constants.TAG_soap_Envelope_LocalName);
                Element header = w3cDoc.createElementNS(Constants.NS_SOAP11, Constants.TAG_soap_Header_LocalName);
                Element body = w3cDoc.createElementNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
                body.setAttributeNS(Constants.NS_WSU10, Constants.ATT_wsu_Id.getLocalPart(), "1");

                header.appendChild(w3cDoc.getDocumentElement());
                w3cDoc.appendChild(envelope);
                envelope.appendChild(header);
                envelope.appendChild(body);

                //transformer.transform(new DOMSource(w3cDoc), streamResult);

                org.w3c.dom.Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(w3cDoc));
            } catch (Exception e) {

                System.out.println(e);
                if (e instanceof RuntimeException) {
                    transformer.transform(new DOMSource(w3cDoc), new StreamResult(System.out));
                    throw e;
                }
                int i = 0;
                Throwable cause = e;
                while (cause != null && i < 10) {
                    if (cause instanceof NullPointerException) {
                        throw e;
                    }
                    i++;
                    cause = cause.getCause();
                }
            }
        }
    }*/
}
