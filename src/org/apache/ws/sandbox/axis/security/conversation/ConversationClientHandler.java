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
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import java.io.ByteArrayOutputStream;

/**
 * @author Dimuthu, Kau
 *
 */

public class ConversationClientHandler extends BasicHandler {

    private boolean isTokenInMemory = false;
    private int requestCount = 0;
    private RequestSecurityTokenResponse stRes;
    private DerivedKeyCallbackHandler dkcbHandler;
    private int frequency = 2;
    private WSSecurityEngine secEng = null;
    private String uuid = null;

    public ConversationClientHandler() {
        System.out.println("ConversationClientHandler :: created");
        dkcbHandler = new DerivedKeyCallbackHandler();

    }

    public void invoke(MessageContext msg) throws AxisFault {
        System.out.println("ConversationClientHandler :: invoked");
        if (msg.getPastPivot())
            doResponse(msg);
        else
            doRequest(msg);
    }

    /**
     * Do request method behaves in two different was according to the fact that  
     * <li>the Token is in memory</li>
     * <li>the Token is not in memory</li>
     * 
     * <b>If Token is in memory </b> then conversation carried out using it
     * <b>If Token is not in memory </b> then message is signed using clients public key and enrypted using server's public key
     * @param msg
     * @throws AxisFault
     */

    private void doRequest(MessageContext msg) throws AxisFault {
        org.apache.xml.security.Init.init();
        Integer tempInt;
        int frequency;

        SOAPHeader sHeader = null;
        Message sm = msg.getCurrentMessage();
        SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();
        Document doc = null;
        try {
            //take the SOAP message as document
            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();

            //check whether the token is in memory
            if (isTokenInMemory) {

                System.out.println("Token in memory .");

                //add DerivedKeyTokens
                String genID = ConversationUtil.genericID();
                ConversationManager conMan = new ConversationManager();
                conMan.addDerivedKeyToken(doc, uuid, dkcbHandler, genID);

                //add the SCT with just identifier 
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

                //set the SOAP message with DKTOkens as the current message               
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                XMLUtils.outputDOM(doc, os, true);
                String osStr = os.toString();
                sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);

                //create a securitytokenReference pointing to the derived key
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
                msg.setProperty(
                    WSDoAllConstants.ENC_KEY_NAME,
                    stRef.toString());
                msg.setUsername(
                    ConversationUtil.generateIdentifier(uuid, genID));
                msg.setProperty(
                    WSDoAllConstants.ENC_CALLBACK_REF,
                    this.dkcbHandler);
                msg.setProperty(WSDoAllConstants.ACTION, "Encrypt");

                WSDoAllSender wsd = new WSDoAllSender();
                wsd.invoke(msg);

            } else { //Token is not in memory
                this.stRes = new RequestSecurityTokenResponse(doc);
                /*SCT is now created.
                 * 1)Store the identifier in identifier
                 * 2)SCTInfo in dkcbHandler
                 */
                uuid =
                    stRes
                        .getRequestedSecurityToken()
                        .getSecurityContextToken()
                        .getIdentifier();

                isTokenInMemory = true;
                stRes.build(doc);

                //Now encrypting with the base token 
                RequestedProofToken reqProof = stRes.getRequestedProofToken();
                //reqProof.doEncryptProof(doc);

                SecurityContextInfo info =
                    new SecurityContextInfo(
                        stRes
                            .getRequestedSecurityToken()
                            .getSecurityContextToken(),
                        reqProof,
                        1);
                dkcbHandler.addSecurtiyContext(uuid, info);

                ByteArrayOutputStream os = new ByteArrayOutputStream();
                XMLUtils.outputDOM(doc, os, true);
                String osStr = os.toString();
                sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);

            }
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

    /**
     * Called in the response. Since this is handler is suppose to carry out secure conversation
     * if Security Context Token (SCT) is not in the message then it should throw a fault.
     *
     * @param msgContext
     * @throws AxisFault
     */
    private void doResponse(MessageContext msgContext)
        throws AxisFault { //for incoming message
        Document doc = null;
        Message message = msgContext.getCurrentMessage();
        //TODO :: Check ........
        secEng = new WSSecurityEngine();
        SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();

        try {
            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();

        } catch (Exception e) {
            throw new AxisFault(
                "WSDoAllSender: cannot get SOAP envlope from message" + e);
        }

        /*Get the derved key tokens.
         *Add them to the convSession.
         * 
         */
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

            secEng.processSecurityHeader(doc, "", this.dkcbHandler, null);

        } catch (WSSecurityException e1) {
            e1.printStackTrace();
            throw new AxisFault("Error !!!! " + e1.getMessage());
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, os, true);
        sPart.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);
   
    } //do response done 

    /**
     * This is a convienience mehtod that return a SOAP message as document.
     *
     * @param msgContext
     * @return
     * @throws AxisFault
     */

    private Crypto loadEncryptionCrypto() throws AxisFault {
        Crypto crypto = null;
        String encPropFile = "crypto.properties";
        crypto = CryptoFactory.getInstance(encPropFile);
        return crypto;
    }

}
