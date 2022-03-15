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
package org.apache.wss4j.stax.test.saml;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.saml2.core.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import jakarta.xml.soap.SOAPConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests related to handling of custom contents in SAML data structures.
 */
public class CustomContentsTest extends AbstractTestBase {

    @Test
    public void testSubjectConfirmationDataExtensibility() throws Exception {

        OpenSAMLUtil.initSamlEngine();

        // create a data structure with custom contents
        SubjectConfirmationDataBean subjectConfirmationDataBean = new SubjectConfirmationDataBean();
        {
            XSAny element1 = new XSAnyBuilder().buildObject("http://abc", "Foobar", "abc");
            element1.getUnknownAttributes().put(new QName(null, "foo"), "123");
            element1.getUnknownAttributes().put(new QName(null, "bar"), "456");
            element1.getUnknownXMLObjects().add(new XSAnyBuilder().buildObject("http://cde", "Unknown", "cde"));

            XSAny element2 = new XSAnyBuilder().buildObject("http://qpr", "Barfuss", "qpr");
            element2.getUnknownXMLObjects().add(new XSAnyBuilder().buildObject("http://xyz1", "Jacke", "xyz1"));
            element2.getUnknownXMLObjects().add(new XSAnyBuilder().buildObject("http://xyz2", "Hose", "xyz2"));
            element2.getUnknownXMLObjects().add(new XSAnyBuilder().buildObject("http://xyz3", "Kappe", "xyz3"));

            AttributeStatementBean attributeStatementBean1 = new AttributeStatementBean();
            addAttribute(attributeStatementBean1, "name-1", stringValue("value-1"));
            addAttribute(attributeStatementBean1, "name-2", stringValue("value-2"));

            AttributeStatementBean attributeStatementBean2 = new AttributeStatementBean();
            addAttribute(attributeStatementBean2, "name-3", stringValue("value-3"));
            addAttribute(attributeStatementBean2, "name-4", stringValue("value-4"));

            Object unsupported1 = Math.PI;
            Object unsupported2 = null;
            Object unsupported3 = "blabla";

            // From these seven elements, only four shall be present in the resulting token,
            // because three are of unsupported types or equal to null.
            subjectConfirmationDataBean.setAny(Arrays.asList(
                    unsupported1, element1, attributeStatementBean1,
                    unsupported2, element2, attributeStatementBean2,
                    unsupported3));
        }

        // create assertion
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setSubjectName("subject123");
            callbackHandler.setSubjectConfirmationData(subjectConfirmationDataBean);

            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

//            System.out.println(baos.toString());
            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            Element elem = document.getDocumentElement();
            elem = (Element) elem.getElementsByTagNameNS(SOAPConstants.URI_NS_SOAP_1_1_ENVELOPE, "Header").item(0);
            elem = (Element) elem.getElementsByTagNameNS(WSS4JConstants.WSSE_NS, WSS4JConstants.WSSE_LN).item(0);
            elem = (Element) elem.getElementsByTagNameNS(WSS4JConstants.SAML2_NS, Assertion.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
            elem = (Element) elem.getElementsByTagNameNS(WSS4JConstants.SAML2_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
            elem = (Element) elem.getElementsByTagNameNS(WSS4JConstants.SAML2_NS, SubjectConfirmation.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
            elem = (Element) elem.getElementsByTagNameNS(WSS4JConstants.SAML2_NS, SubjectConfirmationData.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
            assertEquals(4, elem.getChildNodes().getLength());

            // Extensibility element 1 -- XMLObject
            elem = (Element) elem.getFirstChild();
            assertEquals("Foobar", elem.getLocalName());
            assertEquals("http://abc", elem.getNamespaceURI());
            assertEquals(3, elem.getAttributes().getLength());
            assertEquals(1, elem.getChildNodes().getLength());

            // Extensibility element 2 -- AttributeStatement
            elem = (Element) elem.getNextSibling();
            assertEquals(AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME, elem.getLocalName());
            assertEquals(2, elem.getChildNodes().getLength());
            assertEquals(Attribute.DEFAULT_ELEMENT_LOCAL_NAME, elem.getFirstChild().getLocalName());
            assertEquals(Attribute.DEFAULT_ELEMENT_LOCAL_NAME, elem.getFirstChild().getNextSibling().getLocalName());

            // Extensibility element 3 -- XMLObject
            elem = (Element) elem.getNextSibling();
            assertEquals("Barfuss", elem.getLocalName());
            assertEquals("http://qpr", elem.getNamespaceURI());
            assertEquals(1, elem.getAttributes().getLength());
            assertEquals(3, elem.getChildNodes().getLength());

            // Extensibility element 4 -- AttributeStatement
            elem = (Element) elem.getNextSibling();
            assertEquals(AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME, elem.getLocalName());
            assertEquals(2, elem.getChildNodes().getLength());
            assertEquals(Attribute.DEFAULT_ELEMENT_LOCAL_NAME, elem.getFirstChild().getLocalName());
            assertEquals(Attribute.DEFAULT_ELEMENT_LOCAL_NAME, elem.getFirstChild().getNextSibling().getLocalName());
        }

        // done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }


    private static void addAttribute(AttributeStatementBean attributeStatement, String attributeName, Object value) {
        AttributeBean attribute = new AttributeBean(null, attributeName, Collections.singletonList(value));
        attribute.setNameFormat(Attribute.UNSPECIFIED);
        attributeStatement.getSamlAttributes().add(attribute);
    }

    private static XSAny stringValue(String s) {
        XSAny value = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        value.setTextContent(s);
        return value;
    }

}