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

import java.net.MalformedURLException;
import java.util.Hashtable;

import javax.xml.rpc.ServiceException;
import javax.xml.soap.SOAPHeaderElement;

import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.message.addressing.Action;
import org.apache.axis.message.addressing.Address;
import org.apache.axis.message.addressing.EndpointReference;
import org.apache.axis.message.addressing.MessageID;
import org.apache.axis.message.addressing.ReplyTo;
import org.apache.axis.message.addressing.To;
import org.apache.axis.message.addressing.uuid.AxisUUIdGenerator;
import org.apache.axis.types.URI;
import org.apache.ws.addressing.uuid.UUIdGeneratorFactory;
import org.apache.ws.axis.security.trust.STSAgent;
import org.apache.ws.axis.security.trust.STSAgentAddressingConfiguration;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.policy.message.token.AppliesTo;
import org.apache.ws.security.trust.RSTRParser;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.message.token.BinarySecret;
import org.apache.ws.security.trust.message.token.Entropy;
import org.apache.ws.security.trust.message.token.RequestSecurityTokenResponse;
import org.w3c.dom.Element;

/**
 * @author Dimuthu
 */
public class UNT2SAMLRequester {
/*
   <wsa:MessageID>
  uuid:6cbf8f57-fef9-4ba0-8607-5a5732c94869
  </wsa:MessageID>
  <wsa:To>http://fabrikam.com/ident1</wsa:To>
  <wsa:Action>
  http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue
  </wsa:Action>

 */	
	Element resp = null;
	private RSTRParser parser= null;
	private String requestNonce = null;
	
	
	private	String ipViaTCMPMon= null;
	private	String realIPAddressReal = null;
	private String realServiceAddress = null;
	
	
	public void peformRST(Hashtable opt){
		  try{
		  	   //This HT will provide the input values to WSDoAllSender
			   Hashtable hts=new Hashtable();            
			   hts.put("user","Alice");
			   hts.put("passwordType","PasswordText");
			   hts.put("passwordCallbackClass","org.apache.ws.axis.samples.trust.secconv.interop.UOM_PWCallBackHandler");
			   hts.put("action","UsernameToken Timestamp");


			   //This HT will provide the input values to WSDoAllReceiver
			   Hashtable htr=new Hashtable();            
			   htr.put("action","Timestamp");
            	
               /* We cannot use addressing as below, because
                * 
                *   In the client side Adddrssing handlers are deployed as global and it keeps
                *   effecting all other messages as well.
                * 
                * Ruchith find a fix for this and we can use your AddressingConfiguration.
//                */
                //Prepare teh addressing configuration
			    STSAgentAddressingConfiguration addConfig = new STSAgentAddressingConfiguration();
		//	    addConfig.setAction("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue");
			    //addConfig.setRepyTo("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"); 	
			   			   
			   /*
			    * Set the address here
			    */
			   STSAgent sTSAgent =new STSAgent(ipViaTCMPMon,hts,htr,null);//Microsoft
			   //STSAgent sTSAgent =new STSAgent("http://localhost:8082/sct/Login",hts,htr,null);//IBM
			   sTSAgent.setRequestTypeElement(TrustConstants.ISSUE_SECURITY_TOKEN);
			   sTSAgent.setTokenTypeElement("http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID");
			   
			   ////////////////////////////////Addressing Headers
			   SOAPEnvelope env = sTSAgent.getEnv();
			   
			   String msgIdValue = "uuid:"+UUIdGeneratorFactory.createUUIdGenerator( AxisUUIdGenerator.class ).generateUUId();//"uuid:678uoo900-90ufd7890-5a5732c94869" ;//+ ConversationUtil.generateNonce(10);
			   MessageID msgid = new MessageID(new URI(msgIdValue));
			   Action action =new Action(new URI("http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue"));
			   To to = new To(new URI(realIPAddressReal));//Microsoft
			   //To to = new To(new URI("http://192.35.232.216:8080/sct/Login"));//IBM
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
			
			   //////////////////////////////End of Addressing Headers
			   
			   
			   AppliesTo appliesTo = new AppliesTo(sTSAgent.getDoc());
			   EndpointReference epr = new EndpointReference(this.realServiceAddress);
			   //EndpointReference epr = new EndpointReference("http://192.35.232.216:8080/sct/Service");//IBM
			   
			   appliesTo.setAnyElement(epr.toDOM(sTSAgent.getDoc()));
               
               this.requestNonce = ConversationUtil.generateNonce(128);
               BinarySecret binSec = new BinarySecret(sTSAgent.getDoc());
               binSec.setTypeAttribute(TrustConstants.BINARY_SECRET_NONCE_VAL);
               binSec.setBinarySecretValue(requestNonce);
               
               Entropy entropy = new Entropy(sTSAgent.getDoc());               
			   entropy.setBinarySecret(binSec);
			   
			   sTSAgent.setAnyElement(appliesTo.getElement());
               sTSAgent.setAnyElement(entropy.getElement());            
			   
			   
			   
			   resp=sTSAgent.request();
               
//			Get the rstr  
			   Element rstrEle = (Element)(resp.getElementsByTagNameNS(TrustConstants.WST_NS, TrustConstants.REQUEST_SECURITY_TOKEN_RESPONSE_LN)).item(0);
			   parser = new RSTRParser();
			   parser.processRSTR(new RequestSecurityTokenResponse(rstrEle)); 
			   
	        
		   } catch (MalformedURLException e) {
			   // TODO Auto-generated catch block
			   e.printStackTrace();
		   } catch (ServiceException e) {
			   // TODO Auto-generated catch block
			   e.printStackTrace();
		   } catch (Exception e) {
			   // TODO Auto-generated catch block
			   e.printStackTrace();
		   }
	   }


	/**
	 * @return
	 */
	public RSTRParser getParser() {
		return parser;
	}

	/**
	 * @param parser
	 */
	public void setParser(RSTRParser parser) {
		this.parser = parser;
	}
	
    /**
     * @return
     */
    public String getRequestNonce() {
        return requestNonce;
    }

    /**
     * @param string
     */
    public void setRequestNonce(String string) {
        requestNonce = string;
    }

	/**
	 * @return
	 */
	public String getIpViaTCMPMon() {
		return ipViaTCMPMon;
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
	public void setIpViaTCMPMon(String string) {
		ipViaTCMPMon = string;
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

}
