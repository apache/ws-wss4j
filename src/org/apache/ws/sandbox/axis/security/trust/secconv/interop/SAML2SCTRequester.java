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

package org.apache.ws.axis.security.trust.secconv.interop;

import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;
import java.util.Vector;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.rpc.ServiceException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.Base64;
import org.apache.axis.message.SOAPEnvelope;

import org.apache.axis.message.addressing.Action;
import org.apache.axis.message.addressing.Address;
import org.apache.axis.message.addressing.Constants;
import org.apache.axis.message.addressing.EndpointReference;
import org.apache.axis.message.addressing.MessageID;
import org.apache.axis.message.addressing.ReplyTo;
import org.apache.axis.message.addressing.To;
import org.apache.axis.message.addressing.uuid.AxisUUIdGenerator;

import org.apache.axis.soap.SOAPConstants;
import org.apache.axis.types.URI;
import org.apache.axis.types.URI.MalformedURIException;
import org.apache.axis.utils.DOM2Writer;

import org.apache.ws.addressing.uuid.UUIdGeneratorFactory;
import org.apache.ws.axis.security.WSDoAllSender;
import org.apache.ws.axis.security.conversation.ConvHandlerConstants;
import org.apache.ws.axis.security.conversation.ConversationClientHandler;
import org.apache.ws.axis.security.trust.STSAgent;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationEngine;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.ConversationManager;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.token.RequestSecurityToken;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSAddTimestamp;
import org.apache.ws.security.message.WSBaseMessage;
import org.apache.ws.security.message.WSSAddSAMLToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.policy.message.token.AppliesTo;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.trust.message.token.BinarySecret;
import org.apache.ws.security.trust.message.token.Entropy;
import org.apache.ws.security.trust.message.token.RequestType;
import org.apache.ws.security.trust.message.token.TokenType;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;

import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import sun.security.x509.KeyIdentifier;

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 *
 */
public class SAML2SCTRequester implements RST_Requester {

    SAMLAssertion saml = null;
    SecurityContextToken sct = null;
    Call call = null;
    SOAPEnvelope env;
    Document doc = null;
    Element sAMLElement = null;
    Document docRes = null;
    
    
	private	String serviceViaTCMPMon= null;
	private	String realIPAddressReal = null;
	private String realServiceAddress = null;
    
    public void peformRST(Hashtable options) {

        /* Actions :: Things that should be done for interop.
         * 
         *  1) Set addressing stuff - msgid, action, to, timestamp, body - DONE
         *  
         *  2) Create the message body, with the following.
         * 		-Token type
         *  	-Request type
         *  	-Applies to
         *  	-Entropy with binary secret.
         * ******************************************* 
         */

        try {
            System.out.println(
                "******************  in SAML2SCT requestor *******");
            Service service = new Service();
            call = (Call) service.createCall();

            env = new SOAPEnvelope();
            

            //creating addressing headers						
            String msgIdValue = "uuid:"+UUIdGeneratorFactory.createUUIdGenerator( AxisUUIdGenerator.class ).generateUUId();
            MessageID msgid = new MessageID(new URI(msgIdValue));
            Action action =
                new Action(
                    new URI("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT"));
            System.out.println(this.realServiceAddress);
            To to = new To(new URI(this.realServiceAddress));
			Address add = new Address("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
			ReplyTo rep = new ReplyTo(add);
			    	
			SOAPHeaderElement sheaderEle = msgid.toSOAPHeaderElement(env,null);
			sheaderEle.setMustUnderstand(true);
			   
			SOAPHeaderElement sheaderEle2=action.toSOAPHeaderElement(env, null);
			sheaderEle2.setMustUnderstand(true);
			   
			SOAPHeaderElement sheaderEle3= to.toSOAPHeaderElement(env, null);
			sheaderEle3.setMustUnderstand(true);
			   
			SOAPHeaderElement sheaderEle4= rep.toSOAPHeaderElement(env, null);
			sheaderEle4.setMustUnderstand(true);
		
			//////// end of addressing headers
            
            
            call.getMessageContext().setMessage(new Message(env));
            
            doc = env.getAsDocument();
            
            // create the RST
            RequestSecurityToken reqSecTok = new RequestSecurityToken(doc);
            TokenType tokenType = new TokenType(doc);
            tokenType.setValue(
                "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct");
			    
            reqSecTok.addToken(tokenType.getElement());

            RequestType requestType = new RequestType(doc);
            requestType.setValue(TrustConstants.ISSUE_SECURITY_TOKEN);
                //"http://schemas.xmlsoap.org/security/trust/Issue");
            reqSecTok.addToken(requestType.getElement());

            //appliesTo
            AppliesTo appliesTo = new AppliesTo(doc);
            //TODO :: Remove hardcoding
            EndpointReference epr =
                new EndpointReference(this.realServiceAddress);//"http://131.107.72.15/Service/Service.ashx");
            appliesTo.setAnyElement(epr.toDOM(doc));
            reqSecTok.addToken(appliesTo.getElement());

            //Entropy and binary secreat    
            
			KeyGenerator keyGen = KeyGenerator.getInstance("2.16.840.1.101.3.4.1.2");
			SecretKey key = keyGen.generateKey();
			 
            BinarySecret binSec = new BinarySecret(doc);
            binSec.setTypeAttribute(BinarySecret.NONCE_VAL);
            binSec.setBinarySecretValue(Base64.encode(key.getEncoded()));
           // binSec.setBinarySecretValue(ConversationUtil.generateNonce(16));
            Entropy entropy = new Entropy(doc);
            entropy.setBinarySecret(binSec);
            reqSecTok.addToken(entropy.getElement());

            Element body =
                (Element) doc.getElementsByTagNameNS(
                    env.getNamespaceURI(),
                    "Body").item(
                    0);
            WSSecurityUtil.appendChildElement(
                doc,
                body,
                reqSecTok.getElement());

        //    System.out.println(
          //      DOM2Writer.nodeToString((Node) doc.getDocumentElement(), true));

        } catch (MalformedURIException e) {
            //TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void createSecurityHeader(
        DerivedKeyCallbackHandler dkcbHandler,
        String uuid)
        throws WSTrustException {
        /*
         * Things to do :
         *  Add two derived Key Tokens.
         *  HMAC signature over msgid,action, to, timestamp, body ** sx1
         *  Encrypt the signature element and body with sx2
         *  Add the SAML token.
         *  Add the Timestamp. 
         */

        //creating the reference to add two derived key tokens to the SAMLToken
        try {
        	
			//Add Timestamp 
			WSAddTimestamp timeStampBuilder = new WSAddTimestamp("", false);
			// add the Timestamp to the SOAP Enevelope
			timeStampBuilder.build(doc, 300); // time in seconds. 5 minutes

			// Add Saml Token
			WSSAddSAMLToken builder = new WSSAddSAMLToken();
			builder.build(doc, saml);

            SecurityTokenReference secTokRef =
                new SecurityTokenReference(WSSConfig.getDefaultWSConfig(), doc);
            Reference ref = new Reference(WSSConfig.getDefaultWSConfig(), doc);
  //         ref.setValueType(
   //             "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID");
	//		ref.setURI(saml.getId()); 
      //      secTokRef.setReference(ref);
			secTokRef.setSAMLKeyIdentifier(saml.getId()); //Changed 05-10-2004 to add the KeyIdentifier element

            ConversationManager man = new ConversationManager();
            System.out.println("Fix NOOOOOOOOWWWWWWW");
        //    dkcbHandler.setDerivedKeyLength(uuid, 16);
            dkcbHandler.setLabelForSession(
                uuid,
                "WS-SecureConversationWS-SecureConversatin");
           
           /* 
			<wsse:SecurityTokenReference>
				  <wsse:Reference 
			 ValueType='http://www.docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertion-1.0' 
				  URI='uuid:8f8a6868-cb87-4d90-8f5d-f6efdb6a83f4' />
				 </wsse:SecurityTokenReference>

            */
            //Create the above segment
            SecurityTokenReference encSTR2Assertion = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),doc);
        //    Reference ref2Assertion = new Reference(WSSConfig.getDefaultWSConfig(),doc); 
		//	ref2Assertion.setValueType("http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID");
		//	ref2Assertion.setURI(this.saml.getId());
		//	encSTR2Assertion.setReference(ref2Assertion);
		encSTR2Assertion.setSAMLKeyIdentifier(this.saml.getId());
			
			//  Create the above segment
		    SecurityTokenReference sigSTR2Assertion = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),(Element)encSTR2Assertion.getElement().cloneNode(true));
		    //TODO :: Find out cloneNode what is true ?
		    //new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),doc);
//			Reference SigRef2Assertion = new Reference(WSSConfig.getDefaultWSConfig(),doc); 
//			SigRef2Assertion.setValueType("http://www.docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertion-1.0");
//			SigRef2Assertion.setURI(this.saml.getId());
//			SigSTR2Assertion.setReference(SigRef2Assertion);
//			   
            //	Add 2 derivedKeyTokens
            DerivedKeyInfo sigDkInfo =
                man.createDerivedKeyToken(doc, uuid, dkcbHandler, sigSTR2Assertion, 16);
            DerivedKeyInfo encDkInfo =
                man.createDerivedKeyToken(doc, uuid, dkcbHandler, encSTR2Assertion, 16);
           
            if(encDkInfo.getSecurityTokenReference()==null){
            	System.out.println("Ok null big problem Fix NOWWWWWWWWWWWW");
            }
           
            //6)HMAC signature over msgid,action, to, timestamp, body ** sx1
            WSEncryptionPart msgidP =
                new WSEncryptionPart(
                    Constants.MESSAGE_ID,
                    Constants.NS_URI_ADDRESSING,
                    "Content");
            WSEncryptionPart actionP =
                new WSEncryptionPart(
                    Constants.ACTION,
                    Constants.NS_URI_ADDRESSING,
                    "Content");
            WSEncryptionPart toP =
                new WSEncryptionPart(
                    Constants.TO,
                    Constants.NS_URI_ADDRESSING,
                    "Content");
            WSEncryptionPart timestampP =
                new WSEncryptionPart(
                    "Timestamp",
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                    "Content");
            WSEncryptionPart bodyP =
                new WSEncryptionPart("Body", env.getNamespaceURI(), "Content");

            Vector vec = new Vector();
            vec.add(msgidP);
            vec.add(actionP);
            vec.add(toP);
            vec.add(timestampP);
            vec.add(bodyP);
            
            
            man.performDK_Sign(doc, dkcbHandler, uuid, sigDkInfo, vec);
            
            /* Steps encrypt the body and the signature.
             * 1) Fist create the SecurityTokenReference to the Derived Key
             * 2) Setup the part vector
             * 3) set up the user
             * 
             * We can now call the method.
             */

            //step 1
            //			SecurityTokenReference secRef = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),doc);
            //			Reference ref2dk = new Reference(WSSConfig.getDefaultWSConfig(),doc);
            //			ref2dk.setValueType("DerivedKeyToken");
            //			ref2dk.setURI(encDkInfo.getId());
            //			secRef.setReference(ref2dk);
            SecurityTokenReference secRef = encDkInfo.getSecTokRef2DkToken();

            //setp 2
           
		 /* 
		  * We cannot do the below.
		  *	WSEncryptionPart bodyEle =
		  *					new WSEncryptionPart("Body", env.getNamespaceURI(), "Element");
          * The error is :
          * org.xml.sax.SAXException: No custom elements allowed at top level until after the &lt;body&gt; tag
          */  
            
            WSEncryptionPart signature =
                new WSEncryptionPart(
                    "Signature",
                    "http://www.w3.org/2000/09/xmldsig#",
                    "Element");
            
			WSEncryptionPart bodyContent =
							new WSEncryptionPart(
								"RequestSecurityToken",
								TrustConstants.WST_NS,
								"Element");
			
		
			Vector encPart = new Vector();					
			//encPart.add(signature);
			encPart.add(bodyContent);
		   

            String encUsr =
                ConversationUtil.generateIdentifier(uuid, encDkInfo.getId());
            man.performDK_ENCR(
                encUsr,
                "",
                true,
                doc,
                secRef,
                dkcbHandler,
                encPart, "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
			// http://131.107.72.15/Service/Service.ashx
			
			
			man.addDkToken(doc,sigDkInfo);
			man.addDkToken(doc,encDkInfo);
			System.out.println(serviceViaTCMPMon);
            call.setTargetEndpointAddress(new URL(this.serviceViaTCMPMon));//"http://localhost:8084/Service/Service.ashx"));
            
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            Message message = call.getMessageContext().getCurrentMessage();
            System.out.println(message.toString());
            SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
            sPart.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);
            call.setProperty(ConvHandlerConstants.DK_CB_HANDLER, dkcbHandler);
            
            call.setClientHandlers(null, new ConversationClientHandler(dkcbHandler));
            
            SOAPEnvelope resp = call.invoke(sPart.getAsSOAPEnvelope());
            
            try {
                this.docRes = resp.getAsDocument();
            } catch (Exception e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            }
           
            //System.out.println("Ok signature is done....");
            //System.out.println(DOM2Writer.nodeToString((Node) doc.getDocumentElement(), true));

        } catch (ConversationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (AxisFault e1) {
            // TODO Auto-generated catch block
         e1.printStackTrace();
        } catch (MalformedURLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }catch(WSSecurityException e){
        
        }

        //7)Encryption.

        //call.set EPR
        //call.invoke();

    }
   
     
    /**
     * @return
     */
    public SAMLAssertion getSaml() {
        return saml;
    }

    /**
     * @param assertion
     */
    public void setSaml(SAMLAssertion assertion) {
        saml = assertion;
    }

    /**
     * @return
     */
    public SecurityContextToken getSct() {
        return sct;
    }

    /**
     * @param token
     */
    public void setSct(SecurityContextToken token) {
        sct = token;
    }

    /**
     * @return
     */
    public Document getDoc() {
        return doc;
    }

    /**
     * @param document
     */
    public void setDoc(Document document) {
        doc = document;
    }

    /**
     * @return
     */
    public Element getSAMLElement() {
        return sAMLElement;
    }

    /**
     * @param element
     */
    public void setSAMLElement(Element element) {
        sAMLElement = element;
    }

    /**
     * @return
     */
    public Document getDocRes() {
        return docRes;
    }

    /**
     * @param document
     */
    public void setDocRes(Document document) {
        docRes = document;
    }

		/**
	 * @return
	 */
	public String getRealIPAddressReal() {
		return realIPAddressReal;
	}

	/**
	 * @return
	 */
	public String getRealServiceAddress() {
		return realServiceAddress;
	}

	
	/**
	 * @param string
	 */
	public void setRealIPAddressReal(String string) {
		realIPAddressReal = string;
	}

	/**
	 * @param string
	 */
	public void setRealServiceAddress(String string) {
		realServiceAddress = string;
	}

	/**
	 * @return
	 */
	public String getServiceViaTCMPMon() {
		return serviceViaTCMPMon;
	}

	/**
	 * @param string
	 */
	public void setServiceViaTCMPMon(String string) {
		serviceViaTCMPMon = string;
	}

}
