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

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Stack;
import java.util.Vector;

import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;

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

import org.apache.ws.security.conversation.ConvEngineResult;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationEngine;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.ConversationManager;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.StringUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

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
    
    public ConversationServerHandler() {
        log.debug("ConversationServerHandler :: created");
    }
    
    static{
		org.apache.xml.security.Init.init();

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
        
        Boolean verify_trust = new Boolean((String)getOption(ConvHandlerConstants.VERIFY_TRUST));
        
        if(verify_trust.booleanValue()==true){
			String trustPropFile = (String)getOption(ConvHandlerConstants.TRUST_ENGINE_PROP);
          
        }
        

        // Get the soap message as a Docuemnt
        SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
        try {
            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();
        } catch (Exception e) {
            e.printStackTrace();
        }
		
		if((this.configurator = (HashMap)msg.getProperty("PolicyObject"))==null){
			log.debug("ConversationServerHandler :: I am configuring");
		       initSessionInfo(); // load values to this.configurator from wsdd
		}
		
		soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        ConversationEngine eng = new ConversationEngine(this.configurator);
         
        try {
        	//TODO :: Process results and fix the scratch
            Vector results = eng.processSecConvHeader(doc, "", dkcbHandler);
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
				    if(stk.isEmpty()){
				    	throw new AxisFault("Action mismatch");
				    }
				    
				    act =((Integer)stk.pop()).intValue();
				    if(act == ConversationConstants.DK_ENCRYPT){
				    	//fine do nothing
				    }else{
				    	throw new AxisFault("Mismatch action order");
				    }
				break;
				
				case ConvEngineResult.SIGN_DERIVED_KEY :
				log.debug("ConversationServerHandler :: Found dk_sign result");
					if(stk.isEmpty()){
						throw new AxisFault("Action mismatch");
					}
					act =((Integer)stk.pop()).intValue();
					if(act == ConversationConstants.DK_SIGN){
					    //fine do nothing
					}else{
						throw new AxisFault("Mismatch action order");
					}
				break;
				
				case ConvEngineResult.SCT :
				log.debug("ConversationServerHandler :: Found SCT result");
				uuid = convResult.getUuid();
				break;
				
				}
				}
			
			if(uuid.equals("")){
				throw new AxisFault("ConversationServerHandler :: Cannot find Session.");
			}
		    
		    if(!rstr){
		    if(!stk.isEmpty()){
			  throw new AxisFault("Action mismatch. Required action missing");
			}
            }
			msg.setProperty(ConversationConstants.IDENTIFIER,uuid);
        
        
        
//        NodeList ndlist = doc.getElementsByTagNameNS(ConversationConstants.WSC_NS,"SecurityContextToken");
//        
//       try {
//             SecurityContextToken sct = new SecurityContextToken((Element)ndlist.item(0));
//		msg.setProperty(ConversationConstants.IDENTIFIER,uuid);
//        } catch (WSSecurityException e2) {
//            // TODO Auto-generated catch block
//            e2.printStackTrace();
//        }
        
        
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

    } //do request

	  /**
		* This method is called in the response. 
		* This method should
		* 1) Add derived keys to the message as required.
		* 2) Sign/encrypt as required.
		*
		* @param msgContext
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
            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();
        } catch (Exception e) {
            e.printStackTrace();
            throw new AxisFault("CovnersationServerHandler :: "+e.getMessage());
        }

        //get the uuid
        uuid = (String) msg.getProperty(ConversationConstants.IDENTIFIER);
        
        if (uuid == null) {
        	//TODO :: throw exception
            System.out.println("UUID NULl line :: 221");
        }
        
  
		try {

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
			  ConversationManager manager = new ConversationManager();
			  
			  for (int i = 0; i < this.actionsInt.length; i++) {
				  // Derrive the token
				  DerivedKeyInfo dkInfo =
					  manager.addDerivedKeyToken(doc, uuid, dkcbHandler);

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
						  dkcbHandler);
				  } else if(actionsInt[i]==ConversationConstants.DK_SIGN){
					  manager.performDK_Sign(doc, dkcbHandler, uuid, dkInfo);
				  }

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
		(String) getOption(ConvHandlerConstants.USE_FIXED_KEYLEN))
		!= null) {
		log.debug("Boolean FixedKeyLegnth is set ::" + tmpStr);

		Boolean fixed = new Boolean(tmpStr);
		this.configurator.put(ConvHandlerConstants.USE_FIXED_KEYLEN, fixed);

		if (fixed.booleanValue()) {
			//Following has to be specified.
			if ((tmpStr =
				(String) getOption(ConvHandlerConstants.KEY_LEGNTH))
				!= null) {

				log.debug("Key Frequency is set ::" + tmpStr);
				this.configurator.put(
					ConvHandlerConstants.KEY_LEGNTH,
					new Long(tmpStr));

			} else {
				throw new AxisFault("If fixed keys are set then set the key legnth too.");
			}

		} else {
			// TODO :: add all the "MUST" parameters for variable keys
		}
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
