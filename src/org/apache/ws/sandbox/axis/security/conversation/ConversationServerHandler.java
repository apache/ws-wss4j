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

package org.apache.ws.axis.security.conversation;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.handlers.BasicHandler;
import org.apache.ws.axis.security.WSDoAllConstants;
import org.apache.ws.axis.security.WSDoAllSender;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.ConversationManager;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org.apache.ws.security.conversation.message.token.RequestSecurityTokenResponse;
import org.apache.ws.security.conversation.message.token.RequestedProofToken;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;

/**
 * Serverside handler that implements WS-Secure Conversation for Axis.
 * 
 * @author Dimuthu
 *
 * Each application has a set of policies on how it should be accessed.
 * This handler facilitates one of the following two types of base tokens for a service 
 * 	1) username token.
 *  2) X509 certificates.
 */
public class ConversationServerHandler extends BasicHandler {
    
    private static DerivedKeyCallbackHandler dkcbHandler;
    
    /**
     * Contains the set of SecurityContextTokens of clients that access the service at this moment.
     * 
     */
    public ConversationServerHandler() {
        System.out.println("ConversationServerHandler :: created");
        dkcbHandler = new DerivedKeyCallbackHandler();
    }

    public void invoke(MessageContext msg) throws AxisFault {
        System.out.println("ConversationServerHandler :: invoked");
        if (msg.getPastPivot())
            doResponse(msg);
        else
            doRequest(msg);
    }

    /**
     * Method looks for a SCT in the SOAP envelope, 
     * <li>		Case 1 :: if it is available then this is the first round.<\li>
     * <li>		Case 2 :: if it is not available check for derived keys<\li>
     * 
     * Case 1 :: Creating a new conversation session and add it to the <code>DerivedKeyCallBackHandler</code> 
     * 
     * Case 2 :: Then call a method <></code> derived key decryption.
     * @param msg
     * @throws AxisFault
     */
    private void doRequest(MessageContext msg) throws AxisFault {

        try {
            Document doc = null;
            Message message = msg.getCurrentMessage();
            RequestSecurityTokenResponse stRes;

            // Code to get the soap message as a Docuemnt
            SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();

            //Now search for a SCT in the Security header.		
            NodeList list =
                doc.getElementsByTagNameNS(
                    WSConstants.WSSE_NS,
                    TrustConstants.SECURITY_CONTEXT_TOKEN_RESPONSE_LN);
            int len = list.getLength();
            if (len == 0) { // No SCT is found
                //	TODO:: Look for derived keys and do the decryption
                try {
                    NodeList ndList =
                        doc.getElementsByTagNameNS(
                            WSConstants.WSSE_NS,
                            "DerivedKeyToken");
                    Element tmpE;
                    DerivedKeyToken tmpDKT;
                    String tmpID;
                    for (int i = 0; i < ndList.getLength(); i++) {
                        tmpE = (Element) ndList.item(i);
                        tmpDKT = new DerivedKeyToken(tmpE);
                        tmpID = tmpDKT.getID();
                        //Add to the conv Session .... :-)					        
                    }
                    WSSecurityEngine secEng = new WSSecurityEngine();
                    secEng.processSecurityHeader(
                        doc,
                        "",
                        dkcbHandler,
                        null);

                } catch (WSSecurityException e1) {
                    e1.printStackTrace();
                    throw new AxisFault("Error !!!! " + e1.getMessage());
                }

            } else {

                Element elem = (Element) list.item(0);
                stRes = new RequestSecurityTokenResponse(elem);

                System.out.println(
                    "SecurityTokenResponse Found :: " + stRes.toString());

                // get securityContextToken, requestedProofToken
                SecurityContextToken SCT =
                    stRes.getRequestedSecurityToken().getSecurityContextToken();
                RequestedProofToken proofToken = stRes.getRequestedProfToken();

                //TODO:: romove the hard coded decryption
                proofToken.doDecryption(
                    "org.apache.ws.axis.oasis.PWCallback",
                    loadEncryptionCrypto());

                SecurityContextInfo scInfo =
                    new SecurityContextInfo(SCT, proofToken, 1);
                scInfo.setSharedSecret(proofToken.getSharedSecret());
                dkcbHandler.addSecurtiyContext("uuid:secureZone", scInfo);

                //Set the stuff in msgContext.
                msg.setProperty("WSSecureConversation.ID", SCT.getIdentifier());

            }
            // Replace sPart with the new sPart.
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            String osStr = os.toString();
            sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);

            //Following sets the headers as processed.
            SOAPHeader sHeader = null;
            try {
                sHeader = message.getSOAPEnvelope().getHeader();
            } catch (Exception ex) {
                throw new AxisFault(
                    "WSDoAllReceiver: cannot get SOAP header after security processing",
                    ex);
            }
            String actor = null;
            Iterator headers = sHeader.examineHeaderElements(actor);

            SOAPHeaderElement headerElement = null;
            while (headers.hasNext()) {
                SOAPHeaderElement hE = (SOAPHeaderElement) headers.next();
                if (hE.getLocalName().equals(WSConstants.WSSE_LN)
                    && hE.getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                    headerElement = hE;
                    break;
                }
            }
            (
                (
                    org
                        .apache
                        .axis
                        .message
                        .SOAPHeaderElement) headerElement)
                        .setProcessed(
                true);
        } catch (AxisFault e) {
            e.printStackTrace();
        } catch (WSSecurityException e) {
            e.printStackTrace();
        } catch (SOAPException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    } //do request

    private void doResponse(MessageContext msg) throws AxisFault {

        System.out.println("Doing response .... ");
        Document doc = null;
        Message message = msg.getCurrentMessage();
        String uuid, identifier;
        //	Code to get the soap message as a Docuemnt
        SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
        try {

            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();

            //get the uuid
            uuid = (String) msg.getProperty("WSSecureConversation.ID");

            // Derrive the token 
            ConversationManager manager = new ConversationManager();
            String genID = ConversationUtil.genericID();
            manager.addDerivedKeyToken(doc, uuid, dkcbHandler, genID);

            //add the relavent SCT
            Element securityHeader =
                WSSecurityUtil.findWsseSecurityHeaderBlock(
                    WSSConfig.getDefaultWSConfig(),
                    doc,
                    doc.getDocumentElement(),
                    false);
            WSSecurityUtil.appendChildElement(
                doc,
                securityHeader,
                (new SecurityContextToken(doc, uuid)).getElement());

            org.apache.xml.security.Init.init();

            //set it as current message
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            String osStr = os.toString();
            sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);

            //Creating wsse:Reference
            Reference ref = new Reference(WSSConfig.getDefaultWSConfig(), doc);
            ref.setURI("#" + genID);
            ref.setValueType("DerivedKeyToken");
            SecurityTokenReference stRef = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),doc);
            stRef.setReference(ref);

            //set mesage properties
            msg.setProperty(
                WSDoAllConstants.ENC_PROP_FILE,
                "crypto.properties");
            msg.setProperty(WSDoAllConstants.ENC_KEY_ID, "EmbeddedKeyName");
            msg.setProperty(WSDoAllConstants.ENC_KEY_NAME, stRef.toString());
            msg.setUsername(ConversationUtil.generateIdentifier(uuid, genID));
            msg.setProperty(
                WSDoAllConstants.ENC_CALLBACK_REF,
                dkcbHandler);
            msg.setProperty(WSDoAllConstants.ACTION, "Encrypt");

            WSDoAllSender wsd = new WSDoAllSender();
            wsd.invoke(msg);
        } catch (AxisFault e) {
            e.printStackTrace();
        } catch (SOAPException e) {
            e.printStackTrace();
        } catch (ConversationException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    } //doResponse

    //TODO :: Remove this. Temporary method.
    private Crypto loadEncryptionCrypto() throws AxisFault {
        Crypto crypto = null;
        String encPropFile = "crypto.properties";

        crypto = CryptoFactory.getInstance(encPropFile);
        return crypto;
    }

}
