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
package org.swssf.xmlsec.test;

import org.swssf.xmlsec.config.Init;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.net.URL;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UncategorizedTest {

    @Test
    public void testConfigurationLoadFromUrl() throws Exception {
        URL url = this.getClass().getClassLoader().getResource("testdata/c14n/in/31_input.xml");
        try {
            Init.init(url);
            Assert.fail();
        } catch (XMLSecurityException e) {
            Assert.assertEquals(e.getMessage(), "General security error; nested exception is: \n" +
                    "\tjavax.xml.bind.UnmarshalException\n" +
                    " - with linked exception:\n" +
                    "[org.xml.sax.SAXParseException: cvc-elt.1: Cannot find the declaration of element 'doc'.]");
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

        Result streamResult = new StreamResult(new FileOutputStream("xml.xml", true));

        XMLSecurityProperties securityProperties = new XMLSecurityProperties();
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());

        while (true) {
            try {
                Document doc = xmlGen.getRandom("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security");

                w3cDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();

                transformer.transform(new DocumentSource(doc), new DOMResult(w3cDoc));

                Element envelope = w3cDoc.createElementNS(XMLSecurityConstants.NS_SOAP11, XMLSecurityConstants.TAG_soap_Envelope_LocalName);
                Element header = w3cDoc.createElementNS(XMLSecurityConstants.NS_SOAP11, XMLSecurityConstants.TAG_soap_Header_LocalName);
                Element body = w3cDoc.createElementNS(XMLSecurityConstants.NS_SOAP11, XMLSecurityConstants.TAG_soap_Body_LocalName);
                body.setAttributeNS(XMLSecurityConstants.NS_WSU10, XMLSecurityConstants.ATT_wsu_Id.getLocalPart(), "1");

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
