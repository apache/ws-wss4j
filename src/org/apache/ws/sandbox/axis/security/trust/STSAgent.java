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

package org.apache.ws.axis.security.trust;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;

import javax.xml.rpc.ServiceException;

import org.apache.axis.AxisFault;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.message.SOAPBodyElement;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.message.addressing.AddressingHeaders;
import org.apache.axis.message.addressing.Constants;
import org.apache.axis.message.addressing.handler.AddressingHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.WSDoAllReceiver;
import org.apache.ws.axis.security.WSDoAllSender;
import org.apache.ws.security.trust.message.token.RequestSecurityToken;
import org.apache.ws.security.trust.message.token.RequestType;
import org.apache.ws.security.trust.message.token.TokenType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Malinda Kaushalye
 * @author Ruchith (ruchith.fernando@gmail.com)
 * 
 * STSAgent is an axis specific component resides in the client side to request a token.
 * The main task is to act as an Agent on behalf of the STS.
 * 
 * 
 */
public class STSAgent {
    
	static Log log = LogFactory.getLog(STSAgent.class.getName());
    
	private String url;
    private RequestSecurityToken reqSecTok;
    private Document doc;
    private SOAPEnvelope env;
    private Call call;
    
 /**
  * Agent initialization
  * @param url Endpoint Address
  * @param senderOptions WSDoAllSender options
  * @param recieverOptions WSDoAllReceiver options
  * @param addConfig Addressing configuration for the STSAgent
  * @throws ServiceException
  * @throws MalformedURLException
  * @throws Exception
  * 
  * @see org.apache.ws.axis.security.WSDoAllReceiver
  * @see org.apache.ws.axis.security.WSDoAllSender
  * @see STSAgentAddressingConfiguration
  */
    public STSAgent(String url,Hashtable senderOptions,Hashtable receiverOptions, STSAgentAddressingConfiguration addConfig)throws ServiceException,MalformedURLException,Exception{
		Service service = new Service();
		call = (Call) service.createCall();
		//--
		
		WSDoAllSender doAllSender=new WSDoAllSender();
		WSDoAllReceiver doAllReciever=new WSDoAllReceiver();
		
		// if there are options to encrypt and sign hand them over to WSDoAllSender/Reciever
		if(senderOptions !=null){
		    log.debug("WSDoAllSender options are null");
			doAllSender.setOptions(senderOptions);			 
		}
		if(receiverOptions !=null){
		    log.debug("WSDoAllReceiver options are null");
			doAllReciever.setOptions(receiverOptions);		
		}
		call.setClientHandlers(doAllSender,doAllReciever);
	
		if(addConfig != null) { //If the addressing configuration is provided
			System.out.println("Tired tired tired");
			AddressingHandler addressingHandler = new AddressingHandler();
			addressingHandler.setOption("removeHeaders","false");
			AddressingHeaders headers = addConfig.getHeaders();
			call.setProperty(Constants.ENV_ADDRESSING_REQUEST_HEADERS, headers);
			call.setClientHandlers(addressingHandler,addressingHandler);
		}

		/*
		 SET SECURITY HANDLERS
			These should be added last at the client side since the 
			WSDoAllSender should be executed last in the request flow and the
			WSDoAllreceiver should be executed first in the response flow
		*/
		
		//call.setClientHandlers(doAllSender,null);
		
		//--
		this.url=url;
		call.setTargetEndpointAddress(new URL(url));
		log.debug("Endpoint Address : "+url);
		env = new SOAPEnvelope();
		doc = env.getAsDocument();
		reqSecTok=new RequestSecurityToken(doc);
    }
    

    /**
     * Agent initialization without addressing support
     * I don't think this will be used at all :-?
     * @param url
     * @param senderOptions
     * @param receiverOptions
     * @throws ServiceException
     * @throws MalformedURLException
     * @throws Exception
     */
    public STSAgent(String url,Hashtable senderOptions,Hashtable receiverOptions)throws ServiceException,MalformedURLException,Exception{
    	this(url,senderOptions,receiverOptions,null);
    }
    
    /**
     * Sets token type element
     * @param value
     */
    public void setTokenTypeElement(String value){
        TokenType tokenType=new TokenType(this.doc);
        tokenType.setValue(value);
        this.reqSecTok.addToken(tokenType.getElement());
    }
    /**
     * Sets request type element
     * @param value
     */
    public void setRequestTypeElement(String value){
        RequestType requestType=new RequestType(this.doc);
        requestType.setValue(value);
        this.reqSecTok.addToken(requestType.getElement());
    }
    /**
     * Use this method to add any element to the request
     * @param element
     */
    public void setAnyElement(Element element){
        this.reqSecTok.addToken(element);
    }
    

    /**
     * request call
     * Thank goes to David Del Vecchio for giving his code(=>idea)
     * 
     * @return 
     * @throws AxisFault
     * @throws Exception
     */
    public Element request()throws AxisFault,Exception{
		SOAPBodyElement sbe = new SOAPBodyElement(reqSecTok.getElement());
		this.env.addBodyElement(sbe);
		log.debug("Invoke");
		SOAPEnvelope response = call.invoke(env);
		Element responseElement =response.getAsDOM();
		return responseElement;
    }
    

    public Document getDoc() {
        return this.doc;
    }
    public SOAPEnvelope getEnv() {
        return this.env;
    }
    
	public void setEnv(SOAPEnvelope e) throws Exception {
		this.env=e;
		this.doc=env.getAsDocument();
    }
    
    public RequestSecurityToken getReqSecTok() {
        return this.reqSecTok;
    }
    public void setReqSecTok(RequestSecurityToken reqSecTok) {
        this.reqSecTok = reqSecTok;
    }
    /**
     * to retrieve the endpoint url of the agent
     * @return 
     */
    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
