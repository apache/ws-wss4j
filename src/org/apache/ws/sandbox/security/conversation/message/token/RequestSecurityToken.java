/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.security.conversation.message.token;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPMessage;

/**
 * Class RequestSecurityToken
 */
public class RequestSecurityToken {

    /**
     * Field message
     */
    private SOAPMessage message;

    /**
     * Field reqType
     */
    private String reqType;

    /**
     * Field tokenType
     */
    private String tokenType;

    /**
     * Field doc
     */
    private Document doc;

    /**
     * Field token
     */
    private Element token;

    /**
     * Constructor RequestSecurityToken
     * 
     * @param element 
     * @throws WSSecurityException 
     */
    public RequestSecurityToken(Element element) throws WSSecurityException {
        // TODO :: Support only for SCT - for now
        token = (Element) WSSecurityUtil.getDirectChild(element,
                TrustConstants.SECURITY_CONTEXT_TOKEN_LN, WSConstants.WSSE_NS);
        SecurityContextToken sct = new SecurityContextToken(token);
    }

    /**
     * Constructor RequestSecurityToken
     * 
     * @param message   
     * @param tokenType 
     * @param reqType   
     * @throws Exception 
     */
    public RequestSecurityToken(SOAPMessage message, String tokenType, String reqType)
            throws Exception {
        this.message = message;
        this.tokenType = tokenType;
        this.reqType = reqType;
        this.processDocuement();
    }

    /**
     * Method processDocuement
     * 
     * @throws Exception 
     */
    private void processDocuement() throws Exception {
        // SOAPElement reqSecToken = this.message.getSOAPPart().getEnvelope().getBody().addChildElement("RequestSecurityToken");
        this.message.getSOAPPart().getEnvelope().getBody().detachNode();
        SOAPElement reqSecToken =
                this.message.getSOAPPart().getEnvelope().addBody().addChildElement("RequestSecurityToken");
        System.out.println("Body : "
                + this.message.getSOAPPart().getEnvelope().getBody().toString());

        // Creating the TokenType element
        SOAPElement tokenTypeElement = reqSecToken.addChildElement("TokenType");
        tokenTypeElement.addTextNode(this.tokenType);

        // Creating the RequestType element
        SOAPElement requestTypeElement =
                reqSecToken.addChildElement("RequestType");
        requestTypeElement.addTextNode(this.reqType);
        System.out.println("My Body : " + this.message.getSOAPPart().getEnvelope().getBody());
    }

    // public RequestSecurityToken(Document doc,String tokenType, String reqType) throws Exception{
    // this.doc = doc;
    // this.tokenType = tokenType;
    // this.reqType = reqType;
    // this.processDocuement();
    // }
    // 
    // private void processDocuement() throws Exception{
    // SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
    // Element bodyElement =
    // (Element) WSSecurityUtil.getDirectChild(
    // doc.getFirstChild(),
    // soapConstants.getBodyQName().getLocalPart(),
    // soapConstants.getEnvelopeURI());
    // if (bodyElement == null) {
    // throw new Exception("SOAP Body Element node not found");
    // }
    // 
    // Element reqSecToken = doc.createElement("RequestSecurityToken");
    // 
    // //Creating the TokenType element
    // Element tokenTypeElement = doc.createElement("TokenType");
    // tokenTypeElement.appendChild(doc.createTextNode(this.tokenType));
    // 
    // //Creating the RequestType element
    // Element requestTypeElement = doc.createElement("RequestType");
    // requestTypeElement.appendChild(doc.createTextNode(this.reqType));
    // 
    // //Adding the elements into RequestSecurityToken element
    // reqSecToken.appendChild(tokenTypeElement);
    // reqSecToken.appendChild(requestTypeElement);
    // 
    // }
}
