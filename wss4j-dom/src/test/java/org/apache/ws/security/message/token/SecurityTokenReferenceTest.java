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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.util.DOM2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Some tests for the SecurityTokenReference class.
 */
public class SecurityTokenReferenceTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SecurityTokenReferenceTest.class);
    
    /**
     * Test for a Reference with no URI
     */
    @org.junit.Test
    public void testReferenceNoURI() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        Reference ref = new Reference(doc);
        ref.setValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        ref.setURI(null);
        str.setReference(ref);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(str.toString());
        }
        
        // Process the STR
        Element strElement = str.getElement();
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on a reference with no URI");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("Reference URI is null"));
        }
    }

    /**
     * Test for a SecurityTokenReference having multiple data references
     */
    @org.junit.Test
    public void testMultipleChildren() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        str.setKeyIdentifierEncKeySHA1("123456");
        Element strElement = str.getElement();
        
        Reference ref = new Reference(doc);
        ref.setValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        ref.setURI("#123");
        strElement.appendChild(ref.getElement());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(str.toString());
        }
        
        // Process the STR
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on multiple data references");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("Cannot handle multiple data references"));
        }
        
        new SecurityTokenReference(strElement, false);
    }
    
    /**
     * Test for a SecurityTokenReference having a Key Identifier with no ValueType
     */
    @org.junit.Test
    public void testKeyIdentifierNoValueType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        str.setKeyIdentifier((String)null, "#123");
        Element strElement = str.getElement();

        if (LOG.isDebugEnabled()) {
            LOG.debug(str.toString());
        }
        
        // Process the STR
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on a Key Identifier with no ValueType");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("Bad ValueType"));
        }
        
        new SecurityTokenReference(strElement, false);
    }
    
    /**
     * Test for a SecurityTokenReference having a Key Identifier with a bad EncodingType
     */
    @org.junit.Test
    public void testKeyIdentifierBadEncodingType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        Element strElement = str.getElement();
        
        Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
        keyId.setAttributeNS(null, "ValueType", SecurityTokenReference.ENC_KEY_SHA1_URI);
        keyId.setAttributeNS(null, "EncodingType", "http://bad_encoding");
        keyId.appendChild(doc.createTextNode("#123"));
        strElement.appendChild(keyId);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(str.toString());
        }
        
        // Process the STR
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on a Key Identifier with a Bad EncodingType");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("bad EncodingType"));
        }
        
        new SecurityTokenReference(strElement, false);
    }
    
    
    /**
     * Test for a SecurityTokenReference having a Key Identifier with no EncodingType
     */
    @org.junit.Test
    public void testKeyIdentifierNoEncodingType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        Element strElement = str.getElement();
        
        Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
        keyId.setAttributeNS(null, "ValueType", SecurityTokenReference.ENC_KEY_SHA1_URI);
        keyId.appendChild(doc.createTextNode("#123"));
        strElement.appendChild(keyId);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(str.toString());
        }
        
        // Process the STR
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on a Key Identifier with no EncodingType");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("No EncodingType"));
        }
        
        new SecurityTokenReference(strElement, false);
    }
    
    /**
     * Test for a SecurityTokenReference having a Key Identifier with no EncodingType, but
     * it should pass as the ValueType is for a SAML Assertion.
     */
    @org.junit.Test
    public void testKeyIdentifierSAMLNoEncodingType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        Element strElement = str.getElement();
        
        Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
        keyId.setAttributeNS(null, "ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE);
        keyId.appendChild(doc.createTextNode("#123"));
        strElement.appendChild(keyId);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(str.toString());
        }
        
        // Process the STR
        new SecurityTokenReference(strElement);
    }
    
    /**
     * Test for a SecurityTokenReference having an Embedded Child, which in turn has a 
     * SecurityTokenReference child.
     */
    @org.junit.Test
    public void testEmbeddedSTRChild() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        Element strElement = str.getElement();
        
        Element embedded = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Embedded");
        str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        embedded.appendChild(str.getElement());
        
        strElement.appendChild(embedded);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(DOM2Writer.nodeToString(strElement));
        }
        
        // Process the STR
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on an Embedded Child with a SecurityTokenReference child");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("embedded Reference is invalid"));
        }
        
        new SecurityTokenReference(strElement, false);
    }
    
    /**
     * Test for a SecurityTokenReference having an Embedded Child, which has multiple
     * children.
     */
    @org.junit.Test
    public void testMultipleEmbeddedChildren() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Create the STR
        SecurityTokenReference str = new SecurityTokenReference(doc);
        str.addWSSENamespace();
        Element strElement = str.getElement();
        
        Element embedded = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Embedded");
        Element embedded1 = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Reference");
        Element embedded2 = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Reference");
        embedded.appendChild(embedded1);
        embedded.appendChild(embedded2);
        
        strElement.appendChild(embedded);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(DOM2Writer.nodeToString(strElement));
        }
        
        // Process the STR
        try {
            new SecurityTokenReference(strElement);
            fail("Failure expected on an Embedded Child with multiple children");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("embedded Reference is invalid"));
        }
        
        new SecurityTokenReference(strElement, false);
    }
    
}
