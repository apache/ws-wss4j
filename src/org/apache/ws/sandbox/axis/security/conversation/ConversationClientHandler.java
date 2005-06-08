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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.components.logger.LogFactory;
import org.apache.axis.handlers.BasicHandler;
import org.apache.axis.message.MessageElement;
import org.apache.axis.message.SOAPHeaderElement;
import org.apache.commons.logging.Log;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationEngine;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.ConversationManager;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.trust.message.token.RequestSecurityTokenResponse;
import org.apache.ws.security.trust.message.token.RequestedProofToken;
import org.apache.ws.security.trust.message.token.RequestedSecurityToken;
import org.apache.ws.security.util.StringUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 *
 * This handler performs the client side actions, in order to execute WS-Secure
 * Conversation. It employs three major components;
 * <br /> 1) DerivedKeyCallbackHandler.java - Interfacing to the derived key generation component.
 * <br /> 2) ConversationEngine.java - Process and validate conversation elements.
 * <br /> 3) ConversationClient.java - Creates conversation elements.
 * 
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 * @author Kaushalye Kapruge.  (kaushalye@yahoo.com)
 *
 */

public class ConversationClientHandler extends BasicHandler {
    private static Log log =
        LogFactory.getLog(ConversationClientHandler.class.getName());

    private int keyLen = -1;
    private RequestSecurityTokenResponse stRes;

    private static DerivedKeyCallbackHandler dkcbHandler =
        new DerivedKeyCallbackHandler();

    // private int frequency = 1;
    private WSSecurityEngine secEng = null;
    private static String uuid = null;

    private Crypto serverCrypto = null;
    private String serverAlias = null;
    private Crypto reqCrypto = null;
    private Crypto stsCrypto = null;

    private int sctEstablishment = -1;

    private static boolean handShakeDone = false;
    private boolean isSCTavailabe = false;
    private static boolean isConfigured = false;
    private boolean readCrypto = false;

	private String appliesTo = null;
	
	private boolean isSessionInfoConfigured = false;
	/* 
	 * TODO :: For now we are allowing only fixed sized derived keys
	 */
	private boolean usedFixedKeys = true;
	 
    private HashMap configurator;

    int[] actionsInt;
    static {
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

    public ConversationClientHandler() throws AxisFault {
        log.debug("ConversationClientHandler :: created");
    }
    
    public ConversationClientHandler(DerivedKeyCallbackHandler dk) throws AxisFault {
		dkcbHandler = dk;
		log.debug("ConversationClientHandler :: created");
    }

    /**
     * Method inherited from the BasicHandler.
     * If in the request flow calls the doRequestMetod()
     * else calls the doResponse() method. 
     * 
     */
    public void invoke(MessageContext msg) throws AxisFault {
        log.debug("ConversationClientHandler :: invoked");
        System.out.println("ConversationClientHandler :: invoked");
       if (msg.getPastPivot())
            doResponse(msg);
        else
            doRequest(msg);
    }

    /**
     * The method is called in the request flow.
     * 
     * Do request method behaves in two different was according to the fact that
     * <p>initial handshake is done.</p>
     * <p>OR</p>
     * <p>initial handshake is not done, i.e. SCT is not in memory</p>
     *
     * <br/>If SCT is in memory(handshake is done), then conversation carried out 
     * using it
     * <br/>If Token is not in memory (handshake is not done), the the SCT generation
     * method will be read from the wsdd file. According to the parameters read the 
     * method will execute actions. 
     * @param msg
     * @throws AxisFault
     */

    private void doRequest(MessageContext msg) throws AxisFault {
		if(!isSessionInfoConfigured){
			initSessionInfo();
			isSessionInfoConfigured = true;
		}
        
        Message sm = msg.getCurrentMessage();
        //SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();
        Document doc = null;

        if (!handShakeDone) {

            decodeSCTEstabParameter();
			this.loadCrypto();
           
            switch (this.sctEstablishment) {

                case ConversationConstants.DIRECT_GENERATED :
                    this.doHandshake_Direct_Generated(sm);
                    break;

                case ConversationConstants.STS_GENERATED :
                    this.doHandshake_STS_Generated(sm);
                    break;

                case ConversationConstants.STSREQUEST_TOKEN ://the scenario where STS signs the token.
                    break;
                
//                case ConversationConstants.INTEROP_SCENE1 :
//				    this.doHandlshake_Interop(sm);
//                	break;
                
                default :
                    throw new AxisFault("Unsupored STS establishment method.");

            }

            handShakeDone = true;

        } else { // handshake is done.

            log.debug("Token in memory .");
            SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();
            try {
                doc =
                    ((org.apache.axis.message.SOAPEnvelope) sPart
                        .getEnvelope())
                        .getAsDocument();
            } catch (Exception e) {
                throw new AxisFault("CoversationClientHandler :: Cannot get the document");
            }

            try {

                //				add the relavent SCT
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
                        manager.createDerivedKeyToken(doc, uuid, dkcbHandler,null, keyLen);

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
                            dkcbHandler, null,(String)this.configurator.get(ConvHandlerConstants.DK_ENC_ALGO));
                    } else if(actionsInt[i]==ConversationConstants.DK_SIGN){
                    	//TODO:
                        manager.performDK_Sign(doc, dkcbHandler, uuid, dkInfo, null);
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

        }

    }
    /**
    * This method is called in the response. 
    * If Security Context Token (SCT) is not in the message, then it throws a fault.
    *
    * @param msgContext
    * @throws AxisFault
    */
    private void doResponse(MessageContext msgContext)
        throws AxisFault { //for incoming message
        Document doc = null;
		if(!isSessionInfoConfigured){
			initSessionInfo();
			isSessionInfoConfigured = true;
		}
        Message message = msgContext.getCurrentMessage();
        SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
//        if (!this.readCrypto) {
//            this.loadCrypto();
//        }
        
        Object obj = null; 
        if((obj=msgContext.getProperty(ConvHandlerConstants.DK_CB_HANDLER))!=null){
        	this.dkcbHandler = (DerivedKeyCallbackHandler)obj;
        } 
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
         */

        log.debug("I am in ClientHandler Response");
        
        
        try{
        ConversationEngine convEng = new ConversationEngine(this.configurator);
		Vector results = convEng.processSecConvHeader(doc, "", dkcbHandler, (String)this.configurator.get(WSHandlerConstants.PW_CALLBACK_CLASS));
				} catch (ConversationException e1) {
					e1.printStackTrace();
					throw new AxisFault("CovnersationServerHandler :: "+e1.getMessage());
				}
				
				

//stolen from WSDoallReciever
  ByteArrayOutputStream os = new ByteArrayOutputStream();
		  XMLUtils.outputDOM(doc, os, true);
		  sPart.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);

		  ArrayList processedHeaders = new ArrayList();
				  Iterator iterator = message.getSOAPEnvelope().getHeaders().iterator();
				  while (iterator.hasNext()) {
					  org.apache.axis.message.SOAPHeaderElement tempHeader = (org.apache.axis.message.SOAPHeaderElement) iterator.next();
					  if (tempHeader.isProcessed()) {
						  processedHeaders.add(tempHeader.getQName());
					  }
				  }        
  /*
		   * set the original processed-header flags
		   */
		  iterator = processedHeaders.iterator();
		  while (iterator.hasNext()) {
			  QName qname = (QName) iterator.next();
			  Enumeration enumHeaders = message.getSOAPEnvelope().getHeadersByName(qname.getNamespaceURI(), qname.getLocalPart());
			  while(enumHeaders.hasMoreElements()) {
				  org.apache.axis.message.SOAPHeaderElement tempHeader = (org.apache.axis.message.SOAPHeaderElement)enumHeaders.nextElement();
				  tempHeader.setProcessed(true);
			  }
		  }	  
		
			/*
				   * After setting the new current message, probably modified because
				   * of decryption, we need to locate the security header. That is,
				   * we force Axis (with getSOAPEnvelope()) to parse the string, build 
				   * the new header. Then we examine, look up the security header 
				   * and set the header as processed.
				   * 
				   * Please note: find all header elements that contain the same
				   * actor that was given to processSecurityHeader(). Then
				   * check if there is a security header with this actor.
				   */

				  SOAPHeader sHeader = null;
				  try {
					  sHeader = message.getSOAPEnvelope().getHeader();
				  } catch (Exception ex) {
					  throw new AxisFault("WSDoAllReceiver: cannot get SOAP header after security processing", ex);
				  }

				  Iterator headers = sHeader.examineHeaderElements("");

				  SOAPHeaderElement headerElement = null;
				  while (headers.hasNext()) {
					  SOAPHeaderElement hE = (SOAPHeaderElement) headers.next();
					  if (hE.getLocalName().equals(WSConstants.WSSE_LN)
							  && hE.getNamespaceURI().equals(WSConstants.WSSE_NS)) {
						  headerElement = hE;
						  break;
					  }
				  }
				  ((org.apache.axis.message.SOAPHeaderElement) headerElement).setProcessed(true);

		
		System.out.println("I am in ClientHndelr Response");
          
        
    } //do response done

    /**
     * The method is responsible for generating a SCT. This implements the scenario
     * described in the specification as "Security context token created by 
     * one of the communicating parties and propagated with a message"
     * 
     * @param sm
     * @throws AxisFault
     */
    private void doHandshake_Direct_Generated(Message sm) throws AxisFault {
        Document doc = null;
        SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();
        try {

            log.debug("ConversationClientHandler :: Trust Not required");
            doc =
                ((org.apache.axis.message.SOAPEnvelope) sPart.getEnvelope())
                    .getAsDocument();
            this.initSessionInfo();
            this.stRes = new RequestSecurityTokenResponse(doc, true);

        } catch (Exception e) {
            e.printStackTrace();
            throw new AxisFault(
                "ConversationClientHandler ::" + e.getMessage());
        }

        /*
         * SCT is now created.
         * Steps::
         * 1)
         * 2)SCTInfo in dkcbHandler
         */
        uuid = stRes.getRequestedSecurityToken().getSct().getIdentifier();

        stRes.build(doc);
        isSCTavailabe = true;

        //Now encrypting with the base token
        RequestedProofToken reqProof = stRes.getRequestedProofToken();

        try {
            reqProof.doEncryptProof(doc, this.serverCrypto, this.serverAlias);

            SecurityContextInfo info =
                new SecurityContextInfo(
                    stRes.getRequestedSecurityToken().getSct(),
                    reqProof,
                    ((Integer) (configurator
                        .get(ConvHandlerConstants.KEY_FREQ)))
                        .intValue());

            dkcbHandler.addSecurtiyContext(uuid, info);
            /*
             * Add session specific information to the dkcbHandler
             * 1) Key frequency.
             */
            if (usedFixedKeys == true) {
				Long ln = new Long((String)Integer.toString(keyLen));
                dkcbHandler.setDerivedKeyLength(uuid, ln.longValue() );
            }
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            String osStr = os.toString();
            sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);
        } catch (WSSecurityException e2) {
            e2.printStackTrace();
            throw new AxisFault(
                "ConversationClientHandler ::" + e2.getMessage());
        } catch (ConversationException e2) {
            e2.printStackTrace();
            throw new AxisFault(
                "ConversationClientHandler ::" + e2.getMessage());
        }

    }

    /**
     * This method is repsonsible for obtaining the SCT from the STS.
     * 
     * Firstly, a method call to the STS is done, usig WS-Trust components.  
     * 
     * The STS will return a <RequestedSecurityTokenResponse> that contains 
     * <RequestedProofToken> and <RequestedSecurityToken>
     * 
     * The returned <RequestedProofToken> is decrypted, and again encrypted with the servers
     * certificate to create a new  <RequestedProofToken>.
     * 
     * The recieved <RequestedSecurityToken> and the newly created <RequestedProofToken> is
     * added to the message.
     *    
     *
     * @param sm
     * @throws AxisFault
     */
    private void doHandshake_STS_Generated(Message sm) throws AxisFault {
        Document doc = null;
        MessageElement[] meArrRes = null;
        String tmpStr = null;
		String stsEndPoint, callbackHandler;
		
		
		if ((tmpStr = (String) getOption(ConvHandlerConstants.STS_ADDRESS))
			!= null) {
				stsEndPoint =tmpStr;	    
		}else{
			throw new AxisFault("STS address is not set.");
		}        
        
        if ((tmpStr =(String) getOption(ConvHandlerConstants.APPLIES_TO_VAL))
						!= null) {
							log.debug("Applies to value is read ::" + tmpStr);
				this.appliesTo = tmpStr;			
			}
		
		if ((tmpStr = (String) getOption(ConvHandlerConstants.CONV_CALLBACK))
					!= null) {
						callbackHandler =tmpStr;	    
		}else{
					throw new AxisFault("PasswordCallbackHandler is not set.");
		}
			
//        try {
////            TrustCommunicator tc =
////                new TrustCommunicator(stsEndPoint);
////            
////            tc.requestSecurityToken(
////                new URI(TrustConstants.ISSUE_SECURITY_TOKEN_RST),
////                TokenType.SCT,this.appliesTo);
////            
////            meArrRes = tc.getResponse();
////            log.debug(
////                "TrustCommTester end length of elements in the response is "
////                    + meArrRes.length);
//
//        } catch (MalformedURIException e1) {
//            e1.printStackTrace();
//            throw new AxisFault(
//                "ConversationClientHandler ::" + e1.getMessage());
//        } catch (Exception e1) {
//            e1.printStackTrace();
//            throw new AxisFault(
//                "ConversationClientHandler ::" + e1.getMessage());
//        }

        // We have successfully recieved the message element part.
        SecurityContextToken sct = null;
        RequestedProofToken proof = null;

        log.debug("Trust communitcator successfully completed.");
        try {
            MessageElement tmpEle = null;
            for (int i = 0; i < meArrRes.length; i++) {
                tmpEle = meArrRes[i];
                QName el =
                    new QName(tmpEle.getNamespaceURI(), tmpEle.getLocalName());

                Element domEle = tmpEle.getAsDOM();

                if (el.equals(RequestedSecurityToken.TOKEN)) {
                    log.debug("Recognized RequestedSecurityToken.");

                    NodeList ndList =
                        domEle.getElementsByTagNameNS(
                            SecurityContextToken.TOKEN.getNamespaceURI(),
                            SecurityContextToken.TOKEN.getLocalPart());
                    if (ndList.getLength() < 0) {
                        throw new AxisFault("Unspported yet ..");
                    }
                    sct = new SecurityContextToken((Element) ndList.item(0));

                    SOAPHeader soapHeader = sm.getSOAPHeader();
                    soapHeader.addChildElement(
                        "Security",
                        WSConstants.WSSE_PREFIX,
                        WSConstants.WSSE_NS);

                    Iterator it = soapHeader.getChildElements();
                    while (it.hasNext()) {
                        SOAPHeaderElement shSecElem;
                        if ((shSecElem = (SOAPHeaderElement) it.next())
                            .getLocalName()
                            .equals("Security")) {
                            MessageElement rstr =
                                new MessageElement(
                                    RequestSecurityTokenResponse
                                        .TOKEN
                                        .getLocalPart(),
                                    RequestSecurityTokenResponse
                                        .TOKEN
                                        .getPrefix(),
                                    RequestSecurityTokenResponse
                                        .TOKEN
                                        .getNamespaceURI());
                            rstr.addChild(tmpEle);
                            shSecElem.addChildElement(rstr);
                        }
                    }
                } else if (el.equals(RequestedProofToken.TOKEN)) {
                    SOAPPart sPart =
                        (org.apache.axis.SOAPPart) sm.getSOAPPart();
                    doc =
                        ((org.apache.axis.message.SOAPEnvelope) sPart
                            .getEnvelope())
                            .getAsDocument();
                    //do decrytion - proof is encrypted with certificate of STS 
                    proof = new RequestedProofToken(domEle);
             
             
                    proof.doDecryption(callbackHandler, serverCrypto);

                    byte[] bkArr = proof.getSharedSecret();
                    RequestedProofToken newProof = new RequestedProofToken(doc);
                    newProof.setSharedSecret(bkArr);
                    newProof.doEncryptProof(
                        doc,
                        serverCrypto,
                        this.serverAlias);

                    Element secHeader =
                        WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(),
                            doc,
                            doc.getDocumentElement(),
                            true);

                    Element ele =
                        (Element) WSSecurityUtil.findElement(
                            secHeader,
                            RequestSecurityTokenResponse.TOKEN.getLocalPart(),
                            RequestSecurityTokenResponse
                                .TOKEN
                                .getNamespaceURI());

                    ele.appendChild(newProof.getElement());

                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    XMLUtils.outputDOM(doc, os, true);
                    String osStr = os.toString();
                    sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);

                }

            } //for loop

            this.initSessionInfo();
            Integer keyFreq =
                (Integer) this.configurator.get(ConvHandlerConstants.KEY_FREQ);
            SecurityContextInfo sctInfo =
                new SecurityContextInfo(sct, proof, keyFreq.intValue());
            this.uuid = sct.getIdentifier();
            dkcbHandler.addSecurtiyContext(uuid, sctInfo);

            Boolean isFixedKey =
                (Boolean) configurator.get(
                    ConvHandlerConstants.USE_FIXED_KEYLEN);

            if (this.usedFixedKeys==true) {
                Long keyLen =
                    (Long) this.configurator.get(
                        ConvHandlerConstants.KEY_LEGNTH);
                dkcbHandler.setDerivedKeyLength(uuid, keyLen.longValue());
            }

            handShakeDone = true;

        } catch (WSSecurityException e3) {
            e3.printStackTrace();
            throw new AxisFault(
                "ConversationClientHandler ::" + e3.getMessage());
        } catch (SOAPException e) {
            e.printStackTrace();
            throw new AxisFault(
                "ConversationClientHandler ::" + e.getMessage());
        } catch (Exception e3) {
            e3.printStackTrace();
            throw new AxisFault(
                "ConversationClientHandler ::" + e3.getMessage());
        }

    } //end of doHandshake_STS_Generated


//    private void doHandlshake_Interop(Message sm) throws AxisFault{
//    	
//    	InteropHandshaker interop = new InteropHandshaker();
//		interop.handshake(getOptions()); 
//		//System.out.println("Ok back");
//		this.dkcbHandler = interop.getDkcb(); 
//		
//		this.uuid = interop.getUuid();
//		
//
//		log.debug("Done handlshake .");
//		SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();
//		Document doc = null;
//		
//		try {
//			doc =
//				((org.apache.axis.message.SOAPEnvelope) sPart
//					.getEnvelope())
//					.getAsDocument();
//		} catch (Exception e) {
//			throw new AxisFault("CoversationClientHandler :: Cannot get the document");
//		}
//
//		try {
//
//			//				add the relavent SCT
//			Element securityHeader =
//				WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(),
//					doc,
//					doc.getDocumentElement(),
//					true);
//			WSSecurityUtil.appendChildElement(
//				doc,
//				securityHeader,
//				(new SecurityContextToken(doc, uuid)).getElement());
//			ConversationManager manager = new ConversationManager();
//					
//			for (int i = 0; i < this.actionsInt.length; i++) {
//				// Derrive the token
//				System.out.println("UUID is "+this.uuid);
//				DerivedKeyInfo dkInfo =
//					manager.createDerivedKeyToken(doc, this.uuid, dkcbHandler,null,keyLen);
//
//				String genID = dkInfo.getId();
//				SecurityTokenReference stRef =
//					dkInfo.getSecTokRef2DkToken();
//				if (actionsInt[i] == ConversationConstants.DK_ENCRYPT) {
//					manager.performDK_ENCR(
//						ConversationUtil.generateIdentifier(uuid, genID),
//						"",
//						true,
//						doc,
//						stRef,
//						dkcbHandler, null, (String)this.configurator.get(ConvHandlerConstants.DK_ENC_ALGO));
//				} else if(actionsInt[i]==ConversationConstants.DK_SIGN){
//					//TODO:
//					manager.performDK_Sign(doc, dkcbHandler, uuid, dkInfo, null);
//				}
//
//				manager.addDkToken(doc,dkInfo);
//			}
//		} catch (ConversationException e1) {
//			e1.printStackTrace();
//			throw new AxisFault(
//				"ConversationClientHandler ::" + e1.getMessage());
//		}
//
//		//set it as current message
//		ByteArrayOutputStream os = new ByteArrayOutputStream();
//		XMLUtils.outputDOM(doc, os, true);
//		String osStr = os.toString();
//		sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);
//		
//    }
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
					//throw new AxisFault("Set the pass word call back class.....");
				} 



		if((tmpStr =(String) getOption(ConvHandlerConstants.DK_ENC_ALGO))!= null) {
						this.configurator.put(ConvHandlerConstants.DK_ENC_ALGO, tmpStr);
				}
		
    }

    /**
     * Decodes the SCT establishment parameter set in the .wsdd
     * @throws AxisFault
     */
    private void decodeSCTEstabParameter() throws AxisFault {
        String tmpStr =
            (String) getOption(ConvHandlerConstants.SCT_ESTABLISH_MTD);
        log.debug(
            "ConversationClientHandler :: Decording SCT establishing parameter");
        if (tmpStr.equals(null)) {
            throw new AxisFault("SCT establishing method not specified.");
        } else {
            Integer i =
                (Integer) ConvHandlerConstants.sctEstablishmentMapper.get(
                    tmpStr);
            this.sctEstablishment = i.intValue();
        }
    }
    
    private int decodeSTSRequesterTypeParamer () throws AxisFault{
		String tmpStr =
					(String) getOption(ConvHandlerConstants.STS_REQUSTOR_TYPE);
		log.debug("ConversationClientHandler :: Decording STS requeter type parameter");
		if (tmpStr.equals(null)) {
			throw new AxisFault("STS requeter type not specified.");
		} else {
			Integer i =
				(Integer) ConvHandlerConstants.requesterTypeMapper.get(
					tmpStr);
					return i.intValue();
		}
    }

    /**
     * Loads the crypto property files
     * @throws AxisFault
     */
    private void loadCrypto() throws AxisFault {
        String tmpStr = null;

        if ((tmpStr = (String) getOption(ConvHandlerConstants.SEVER_PROP_FILE))
            == null) {
            throw new AxisFault("Error! No server server properties file in wsdd");
        }

        log.debug("Server prop file is " + tmpStr);

        this.serverCrypto = CryptoFactory.getInstance(tmpStr);

        if ((tmpStr = (String) getOption(ConvHandlerConstants.SEVER_ALIAS))
            == null) {
            throw new AxisFault("Error! No server server properties file in wsdd");
        }
        this.serverAlias = tmpStr;

             
                

    }

    private void decodeDkAction() {

    }

}