/*
 * Created on Aug 18, 2004
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.WSDoAllReceiver;
import org.apache.ws.axis.security.WSDoAllSender;
import org.apache.ws.security.conversation.message.token.RequestSecurityToken;
import org.apache.ws.security.trust.message.token.RequestType;
import org.apache.ws.security.trust.message.token.TokenType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Malinda Kaushalye
 *
 * STSAgent is an axis specific component resides in the client side to request a token.
 * The main task is to act as an Agent on behalf of the STS.
 * 
 * 
 */
public class STSAgent {
    static Log log = LogFactory.getLog(STSAgent.class.getName());
    String url;
    RequestSecurityToken reqSecTok;
    Document doc;
    SOAPEnvelope env;
    Call call;
    
 /**
  * Agent initialization
  * @param url Endpoint Address
  * @param senderOptions WSDoAllSender options
  * @param recieverOptions WSDoAllReceiver options
  * @throws ServiceException
  * @throws MalformedURLException
  * @throws Exception
  * 
  * @see  org.apache.ws.axis.security.WSDoAllReceiver
  * @see  org.apache.ws.axis.security.WSDoAllSender
  */
    public STSAgent(String url,Hashtable senderOptions,Hashtable recieverOptions)throws ServiceException,MalformedURLException,Exception{
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
		if(recieverOptions !=null){
		    log.debug("WSDoAllReceiver options are null");
			doAllReciever.setOptions(recieverOptions);		
		}
		call.setClientHandlers(doAllSender,doAllReciever);  
		//--
		this.url=url;
		call.setTargetEndpointAddress(new URL(url));
		log.debug("Endpoint Address : "+url);
		env = new SOAPEnvelope();
		doc = env.getAsDocument();
		reqSecTok=new RequestSecurityToken(doc);
    }
    
    /**
     * Sets token type element
     * @param value
     */
    public void setTokenTypeElement(String value){
        TokenType tokenType=new TokenType(this.doc);
        tokenType.setValue(value);
        reqSecTok.addToken(tokenType.getElement());
    }
    /**
     * Sets request type element
     * @param value
     */
    public void setRequestTypeElement(String value){
        RequestType requestType=new RequestType(this.doc);
        requestType.setValue(value);
        reqSecTok.addToken(requestType.getElement());
    }
    /**
     * Use this method to add any element to the request
     * @param element
     */
    public void setAnyElement(Element element){
        reqSecTok.addToken(element);
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
		env.addBodyElement(sbe);
		log.debug("Invoke");
		SOAPEnvelope response = call.invoke(env);
		Element responseElement =response.getAsDOM();
		return responseElement;
    }
    

    public Document getDoc() {
        return doc;
    }
    public SOAPEnvelope getEnv() {
        return env;
    }
    public RequestSecurityToken getReqSecTok() {
        return reqSecTok;
    }
    public void setReqSecTok(RequestSecurityToken reqSecTok) {
        this.reqSecTok = reqSecTok;
    }
    /**
     * to retrieve the endpoint url of the agent
     * @return 
     */
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
