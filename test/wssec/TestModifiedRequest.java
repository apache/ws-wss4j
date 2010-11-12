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

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
// import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
// import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.List;
import java.util.Vector;

/**
 * This class tests the modification of requests to see if signature verification fails.
 */
public class TestModifiedRequest extends TestCase implements CallbackHandler {
    private static final Log LOG = LogFactory.getLog(TestModifiedRequest.class);
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        +           "<value xmlns=\"http://blah.com\">15</value>" 
        +       "</add>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance();

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestModifiedRequest(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestModifiedRequest.class);
    }
    
    /**
     * Test that signs a SOAP body element "value". The SOAP request is then modified
     * so that the signed "value" element is put in the header, and the value of the
     * original element is changed. This test will fail as the request will contain
     * multiple elements with the same wsu:Id.
     */
    public void testMovedElement() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new Vector<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "value",
                "http://blah.com",
                "");
        parts.add(encP);
        builder.setParts(parts);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        //
        // Replace the signed element with a modified element, and move the original
        // signed element into the SOAP header
        //
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Element envelopeElement = signedDoc.getDocumentElement();
        org.w3c.dom.Node valueNode = 
            envelopeElement.getElementsByTagNameNS("http://blah.com", "value").item(0);
        org.w3c.dom.Node clonedValueNode = valueNode.cloneNode(true);
        secHeaderElement.appendChild(clonedValueNode);
        valueNode.getFirstChild().setNodeValue("250");
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc);
            fail("Failure expected on multiple elements with the same wsu:Id");
        } catch (Exception ex) {
            // expected
        }
    }
    
    
    /**
     * Test that signs a SOAP body element "value". The SOAP request is then modified
     * so that the signed "value" element is put in the header, and the value of the
     * original element is changed. The wsu:Id value of the original element is also
     * changed. Signature verification will pass, so we need to check that wsu:Id's.
     * TODO - failing after JSR105 move
    public void testMovedElementChangedId() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List parts = new Vector();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "value",
                "http://blah.com",
                "");
        parts.add(encP);
        builder.setParts(parts);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        //
        // Replace the signed element with a modified element, and move the original
        // signed element into the SOAP header
        //
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Element envelopeElement = signedDoc.getDocumentElement();
        org.w3c.dom.Node valueNode = 
            envelopeElement.getElementsByTagNameNS("http://blah.com", "value").item(0);
        org.w3c.dom.Node clonedValueNode = valueNode.cloneNode(true);
        secHeaderElement.appendChild(clonedValueNode);
        valueNode.getFirstChild().setNodeValue("250");
        String savedId = 
            ((org.w3c.dom.Element)valueNode).getAttributeNS(WSConstants.WSU_NS, "Id");
        ((org.w3c.dom.Element)valueNode).setAttributeNS(
             WSConstants.WSU_NS, "wsu:Id", "id-250"
        );
            
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Now we check that the wsu:Id of the element we want signed corresponds to the
        // wsu:Id that was actually signed...again, this should pass
        //
        List results = verify(signedDoc);
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        WSSecurityUtil.checkSignsAllElements(actionResult, new String[]{savedId});
        
        //
        // Finally we need to check that the wsu:Id of the element we want signed in the
        // SOAP request is the same as the wsu:Id that was actually signed
        //
        envelopeElement = signedDoc.getDocumentElement();
        org.w3c.dom.Node bodyNode = 
            envelopeElement.getElementsByTagNameNS(
                WSConstants.URI_SOAP11_ENV, "Body"
            ).item(0);
        valueNode = 
            ((org.w3c.dom.Element)bodyNode).getElementsByTagNameNS(
                "http://blah.com", "value"
            ).item(0);
        String actualId = 
            ((org.w3c.dom.Element)valueNode).getAttributeNS(WSConstants.WSU_NS, "Id");
        try {
            WSSecurityUtil.checkSignsAllElements(actionResult, new String[]{actualId});
            fail("Failure expected on bad wsu:Id");
        } catch (Exception ex) {
            // expected
        }
    }
    */


    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult>  verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, this, crypto);
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                /*
                 * here call a function/method to lookup the password for
                 * the given identifier (e.g. a user name or keystore alias)
                 * e.g.: pc.setPassword(passStore.getPassword(pc.getIdentfifier))
                 * for Testing we supply a fixed name here.
                 */
                pc.setPassword("password");
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
