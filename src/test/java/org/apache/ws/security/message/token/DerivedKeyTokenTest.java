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

package org.apache.ws.security.message.token;

/**
 * Tests for DerivedKeyToken type.
 */

public class DerivedKeyTokenTest extends org.junit.Assert {

    private static final String TEST_TOKEN_TEMPLATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<wsc:DerivedKeyToken "
            + "xmlns:wsc=\"http://schemas.xmlsoap.org/ws/2005/02/sc\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"_3\" >"
            + "<wsse:SecurityTokenReference "
            + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" wsu:Id=\"_5002\">"
            + "<wsse:Reference ValueType=\"http://schemas.xmlsoap.org/ws/2005/02/sc/sct\" URI=\"PLACEHOLDER1\" />"
            + "</wsse:SecurityTokenReference>"
            + "<wsc:Offset>0</wsc:Offset>"
            + "<wsc:Length>PLACEHOLDER2</wsc:Length>"
            + "<wsc:Nonce>Kq/1ptgjZpX2g1q6MiJcSfTX</wsc:Nonce>"
            + "<wsc:Label>WS-SecureConversationWS-SecureConversation</wsc:Label>"
            + "<wsc:Generation>3</wsc:Generation>"
            + "<wsc:Properties>"
            + "<wsc:Name>.../derivedKeySource</wsc:Name>"
            + "</wsc:Properties>"
            + "</wsc:DerivedKeyToken>";

    private DerivedKeyToken token;
    private DerivedKeyToken tokenEqual;
    private DerivedKeyToken tokenNotEqual;
    
    
    public DerivedKeyTokenTest() throws Exception {
        token = new DerivedKeyToken(createReferenceDocument(
                TEST_TOKEN_TEMPLATE,
                "#uuid-4063ae9b-fe66-4e09-a5fb-8fda903f34d8", "16")
                .getDocumentElement());
        tokenEqual = new DerivedKeyToken(createReferenceDocument(
                TEST_TOKEN_TEMPLATE,
                "#uuid-4063ae9b-fe66-4e09-a5fb-8fda903f34d8", "16")
                .getDocumentElement());
        tokenNotEqual = new DerivedKeyToken(createReferenceDocument(
                TEST_TOKEN_TEMPLATE,
                "#uuid-5603ae9b-fe66-4e09-a5fb-8fda903f34d8", "88")
                .getDocumentElement());
    }

    @org.junit.Test
    public void testEquals() throws Exception{
        assertTrue(token.equals(tokenEqual));
        assertTrue(tokenEqual.equals(token));
        assertFalse(token.equals(tokenNotEqual));
        assertFalse(token.equals(null));
        assertFalse(token.equals("string"));        
    }
    
    @org.junit.Test
    public void testHashcode() throws Exception{
        assertEquals(token.hashCode(), tokenEqual.hashCode());
        assertTrue(!(token.hashCode() == tokenNotEqual.hashCode()));
    }

    private static org.w3c.dom.Document createReferenceDocument(
            final String template, final String placeholder1,
            final String placeholder2)
            throws javax.xml.parsers.ParserConfigurationException,
            org.xml.sax.SAXException, java.io.IOException {
        final java.io.InputStream in = new java.io.ByteArrayInputStream(
                template.replaceFirst("PLACEHOLDER1", placeholder1)
                        .replaceFirst("PLACEHOLDER2", placeholder2).getBytes());
        final javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory
                .newInstance();
        factory.setNamespaceAware(true);
        final javax.xml.parsers.DocumentBuilder builder = factory
                .newDocumentBuilder();
        return builder.parse(in);
    }
}
