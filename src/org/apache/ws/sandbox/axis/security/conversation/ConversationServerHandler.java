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

package org.apache.ws.sandbox.axis.security.conversation;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.handlers.BasicHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.sandbox.security.conversation.*;
import org.apache.ws.sandbox.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.sandbox.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.StringUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Stack;
import java.util.Vector;

/**
 * Serverside handler that implements WS-Secure Conversation for Axis.
 *
 *
 * @author Dimuthu Leealarthne. (muthulee@yahoo.com)
 *
 */
public class ConversationServerHandler extends BasicHandler {
    private static Log log =
            LogFactory.getLog(ConversationServerHandler.class.getName());
    private boolean doDebug = false;

    private static DerivedKeyCallbackHandler dkcbHandler =
            new DerivedKeyCallbackHandler();

    private static boolean isConfigured = false;
    private SOAPConstants soapConstants = null;

    private HashMap configurator = new HashMap();

    private int[] actionsInt = null;

    private boolean isSessionInfoConfigured = false;

    private boolean isInitTrustVerified = false;

    private Vector sigParts=null;
    private Vector encParts=null;

    private int keyLen =-1;

    public ConversationServerHandler() {
        log.debug("ConversationServerHandler :: created");
    }

    static{
        org.apache.xml.security.Init.init();
        String Id = "BC";
        if (java.security.Security.getProvider(Id) == null) {
            log.debug("The provider " + Id
                    + " had to be added to the java.security.Security");
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        Transform.init();
        try {
            Transform.register(STRTransform.implementedTransformURI,
                    "org.apache.ws.security.transform.STRTransform");
        } catch (Exception ex) {
        }

    }

    /**
     * Method inherited from the BasicHandler.
     * If in the request flow calls the doRequestMetod()
     * else calls the doResponse() method.
     *
     */
    public void invoke(MessageContext msg) throws AxisFault {
        log.debug("ConversationServerHandler :: invoked");

        if (msg.getPastPivot())
            doResponse(msg);
        else
            doRequest(msg);
    }

    /**
     * Called in the request flow of the request.
     * Method looks for a SecurityToken in the SOAP envelope.
     * Process the header.
     *
     *  @param msg
     * @throws AxisFault
     */
    private void doRequest(MessageContext msg) throws AxisFault {
        if(!isSessionInfoConfigured){
            initSessionInfo();
            isSessionInfoConfigured = true;
        }


        Document doc = null;
        Message message = msg.getCurrentMessage();

        // Get the soap message as a Docuemnt
        SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
        try {
            doc =
                    ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();
        } catch (Exception e) {
            e.printStackTrace();
        }

//		if((this.configurator = (HashMap)msg.getProperty("PolicyObject"))==null){
//			log.debug("ConversationServerHandler :: I am configuring");
//		       initSessionInfo(); // load values to this.configurator from wsdd
//		}

        soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        ConversationEngine eng = new ConversationEngine(this.configurator);

//		try {
//            boolean trustEngineResult = false;
//            		if(!isInitTrustVerified){
//            		String tmpStr = null;
//            			if ((tmpStr = (String) getOption(ConvHandlerConstants.TOKEN_TRUST_VERIFY))
//            						!= null) {
//            			if(Boolean.getBoolean(tmpStr)){
//            			  String trustPropFile = (String) getOption(ConvHandlerConstants.TRUST_ENGINE_PROP);
//            			  TrustEngine trstEngine = new TrustEngine(trustPropFile);
//            			  System.out.println("call the engine here ...");
//            			  trustEngineResult=true;
//            			}
//            			isInitTrustVerified = true;
//                        }
//            		}
//            if(trustEngineResult){
//                 //getUUID and proof of possession
//                 //add it to the derived key token
//            }
//        } catch (WSTrustException e2) {
//            // TODO Auto-generated catch block
//            e2.printStackTrace();
//        }



        try {
            Vector results = eng.processSecConvHeader(doc, "", dkcbHandler, (String)this.configurator.get(WSHandlerConstants.PW_CALLBACK_CLASS));
            ConvEngineResult convResult  = null;
            String uuid = "";

            /*put the actions into a stack to obtain LIFO behavior
            * Rational for using the stack;
            *
            * Consider "Signature Encrypt"
            * Then the ConvEngine Results will be in the order "Encrypt Signature"
            * i.e. ConvEngine reusult containing ConvEngineResult.ENCRYPT_DERIVED_KEY
            * will be before ConvEngineResult.SIGN_DERIVED_KEY
            *
            * Hense I need to read actions in the order of Last in First out - the stack
            *
            * This is same for "Encrypt Signature" visa versa.
            */
            Stack stk = new Stack();
            for(int i=0; i<actionsInt.length ; i++){
                stk.push(new Integer(actionsInt[i]));
            }
            int act = -1;
            boolean rstr = false;
            for(int i=0; i<results.size(); i++){
                convResult=(ConvEngineResult)results.get(i);

                switch(convResult.getAction()){

                    case ConvEngineResult.SECURITY_TOKEN_RESPONSE :
                        log.debug("ConversationServerHandler :: Found RSTR result");
                        uuid = convResult.getUuid();
                        rstr = true;
                        break;

                    case ConvEngineResult.ENCRYPT_DERIVED_KEY :
                        log.debug("ConversationServerHandler :: Found dk_encrypt result");
//				    if(stk.isEmpty()){
//				    	throw new AxisFault("Action mismatch");
//				    }
//
//				    act =((Integer)stk.pop()).intValue();
//				    if(act == ConversationConstants.DK_ENCRYPT){
//				    	//fine do nothing
//				    }else{
//				    	throw new AxisFault("Mismatch action order");
//				    }
                        break;

                    case ConvEngineResult.SIGN_DERIVED_KEY :
                        log.debug("ConversationServerHandler :: Found dk_sign result");
//					if(stk.isEmpty()){
//						throw new AxisFault("Action mismatch");
//					}
//					act =((Integer)stk.pop()).intValue();
//					if(act == ConversationConstants.DK_SIGN){
//					    //fine do nothing
//					}else{
//						throw new AxisFault("Mismatch action order");
//					}
                        break;

                    case ConvEngineResult.SCT :
                        log.debug("ConversationServerHandler :: Found SCT result");
                        uuid = convResult.getUuid();
                        break;

                }
            }

            if(uuid.equals("")||(uuid==null)){
                //throw new AxisFault("ConversationServerHandler :: Cannot find Session.");
            }else{
                msg.setProperty(ConversationConstants.IDENTIFIER,uuid);
            }

//
//		    if(!rstr){
//		    if(!stk.isEmpty()){
//			  throw new AxisFault("Action mismatch. Required action missing");
//			}
//            }


        } catch (ConversationException e1) {
            e1.printStackTrace();
            throw new AxisFault("CovnersationServerHandler :: "+e1.getMessage());
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
                    "ConversatonServerHandler: cannot get SOAP header after security processing",
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

        msg.setProperty(ConvHandlerConstants.DK_CB_HANDLER,dkcbHandler);
    } //do request

    /**
     * This method is called in the response.
     * This method should
     * 1) Add derived keys to the message as required.
     * 2) Sign/encrypt as required.
     *
     * @param msg
     * @throws AxisFault
     */
    private void doResponse(MessageContext msg) throws AxisFault {

        if(!isSessionInfoConfigured){
            initSessionInfo();
            isSessionInfoConfigured = true;
        }

        //System.out.println("Doing response .... ");
        Document doc = null;
        Message message = msg.getCurrentMessage();
        String uuid, identifier;
        //	Code to get the soap message as a Docuemnt
        SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();

        try {
            if ((doc = (Document) msg.getProperty(WSHandlerConstants.SND_SECURITY))
                    == null) {
                doc =
                        ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                        .getAsDocument();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new AxisFault("CovnersationServerHandler :: "+e.getMessage());
        }

        //get the uuid
        uuid = (String) msg.getProperty(ConversationConstants.IDENTIFIER);

        if (uuid == null) {
            //TODO :: throw exception
            System.out.println("UUID NULl line :: 346");
        }


        try {
            ConversationSession session = dkcbHandler.getSession(uuid);

            if(session.isAddBase2Message()){
                //add the relavent SCT
                Element securityHeader =
                        WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(),
                                doc,
                                doc.getDocumentElement(),
                                true);
                WSSecurityUtil.appendChildElement(
                        doc,
                        securityHeader,
                        (new SecurityContextToken(doc, uuid)).getElement());
            }

            ConversationManager manager = new ConversationManager();

            for (int i = 0; i < this.actionsInt.length; i++) {

                // Derrive the token
                SecurityTokenReference stRef2Base = null;
                if(session.getRef2Base()==null){
                    //do nothing
                }else{
                    stRef2Base = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),doc);
                    Reference ref = new Reference(WSSConfig.getDefaultWSConfig(),doc);
                    Reference oldRef = session.getRef2Base();

                    ref.setURI(oldRef.getURI());
                    ref.setValueType(oldRef.getValueType());
                    stRef2Base.setReference(ref);
                }
                DerivedKeyInfo dkInfo =
                        manager.createDerivedKeyToken(doc, uuid, dkcbHandler,stRef2Base, keyLen);

                String genID = dkInfo.getId();
                SecurityTokenReference stRef =
                        dkInfo.getSecTokRef2DkToken();

                if (actionsInt[i] == ConversationConstants.DK_ENCRYPT) {
                    manager.performDK_ENCR(
                            ConversationUtil.generateIdentifier(uuid, genID),
                            "",
                            true,
                            doc,
                            stRef,
                            dkcbHandler, this.encParts, (String)this.configurator.get(ConvHandlerConstants.DK_ENC_ALGO));

                } else if(actionsInt[i]==ConversationConstants.DK_SIGN){
                    //TODO
                    manager.performDK_Sign(doc, dkcbHandler, uuid, dkInfo,this.sigParts);
                }

                manager.addDkToken(doc,dkInfo);

            }
        } catch (ConversationException e1) {
            e1.printStackTrace();
            throw new AxisFault(
                    "ConversationClientHandler ::" + e1.getMessage());
        }

        //set it as current message
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, os, true);
        String osStr = os.toString();
        sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);


    } //doResponse

    /**
     * Conversation parameters are read from the wsdd file.
     * When WS-Policy is implemented, these parameters should be
     * configurable using policy components.
     *
     * @throws AxisFault
     */
    /**
     * Reads configeration parameters from the wsdd file.
     * @throws AxisFault
     */
    private void initSessionInfo() throws AxisFault {
        /**
         * Default values for a session. These will be overriden by WSDD file parameters.
         */
        this.configurator = new HashMap();
        String tmpStr;
        if ((tmpStr = (String) getOption(ConvHandlerConstants.KEY_FREQ))
                != null) {
            log.debug("Key Frequency is set ::" + tmpStr);
            this.configurator.put(
                    ConvHandlerConstants.KEY_FREQ,
                    new Integer(tmpStr));
        }

        if ((tmpStr = (String) getOption(ConvHandlerConstants.DK_ACTION))
                != null) {
            log.debug("Derived Key Action is read ::" + tmpStr);
            String[] action = StringUtil.split(tmpStr, ' ');
            actionsInt = new int[action.length];

            for (int i = 0; i < action.length; i++) {
                if ((action[i]).equalsIgnoreCase("Signature")) {
                    actionsInt[i] = ConversationConstants.DK_SIGN;
                } else if ((action[i]).equalsIgnoreCase("Encrypt")) {
                    actionsInt[i] = ConversationConstants.DK_ENCRYPT;
                }
            }

        }

        if ((tmpStr =
                (String) getOption(ConvHandlerConstants.SEVER_PROP_FILE))
                != null) {
            this.configurator.put(ConvHandlerConstants.SEVER_PROP_FILE, tmpStr);
        }


        if ((tmpStr =
                (String) getOption(ConvHandlerConstants.KEY_LEGNTH))
                != null) {
            log.debug("Key Frequency is set ::" + tmpStr);
            this.keyLen=Integer.parseInt(tmpStr);
            this.configurator.put(ConvHandlerConstants.KEY_LEGNTH, new Long(tmpStr));
        }


        if ((tmpStr =
                (String) getOption(WSHandlerConstants.PW_CALLBACK_CLASS))
                != null) {
            this.configurator.put(WSHandlerConstants.PW_CALLBACK_CLASS, tmpStr);
        }else{
            log.debug("Set the pass word call back class.");
        }

        if ((tmpStr =
                (String) getOption(WSHandlerConstants.SIGNATURE_PARTS))
                != null) {
            this.sigParts = new Vector();
            this.splitEncParts(tmpStr,sigParts);
        }

        if ((tmpStr =(String) getOption(WSHandlerConstants.ENCRYPTION_PARTS))
                != null) {
            this.encParts = new Vector();
            this.splitEncParts(tmpStr,encParts);
        }



        if((tmpStr =(String) getOption(WSHandlerConstants.DEC_PROP_FILE))!= null) {
            this.configurator.put(WSHandlerConstants.DEC_PROP_FILE, tmpStr);
            System.out.println("Decryption properties read");
        }

        if((tmpStr =(String) getOption(ConvHandlerConstants.DK_ENC_ALGO))!= null) {
            this.configurator.put(ConvHandlerConstants.DK_ENC_ALGO, tmpStr);
        }





    }


    /**
     * Extracted from the class <code>org.apache.ws.axis.security.WSDoAllSender.java</code>.
     *
     * @param tmpS
     * @param encryptParts
     * @throws AxisFault
     */
    private void splitEncParts(String tmpS, Vector encryptParts)
            throws AxisFault {

        WSEncryptionPart encPart = null;
        String[] rawParts = StringUtil.split(tmpS, ';');

        for (int i = 0; i < rawParts.length; i++) {
            String[] partDef = StringUtil.split(rawParts[i], '}');

            if (partDef.length == 1) {
                if (doDebug) {
                    log.debug("single partDef: '" + partDef[0] + "'");
                }
                encPart =
                        new WSEncryptionPart(
                                partDef[0].trim(),
                                soapConstants.getEnvelopeURI(),
                                "Content");
            } else if (partDef.length == 3) {
                String mode = partDef[0].trim();
                if (mode.length() <= 1) {
                    mode = "Content";
                } else {
                    mode = mode.substring(1);
                }
                String nmSpace = partDef[1].trim();
                if (nmSpace.length() <= 1) {
                    nmSpace = soapConstants.getEnvelopeURI();
                } else {
                    nmSpace = nmSpace.substring(1);
                }
                String element = partDef[2].trim();
                if (doDebug) {
                    log.debug(
                            "partDefs: '"
                            + mode
                            + "' ,'"
                            + nmSpace
                            + "' ,'"
                            + element
                            + "'");
                }
                encPart = new WSEncryptionPart(element, nmSpace, mode);
            } else {
                throw new AxisFault(
                        "WSDoAllSender: wrong part definition: " + tmpS);
            }
            encryptParts.add(encPart);
        }
    }



}
