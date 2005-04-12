/*
 * Created on Aug 29, 2004
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.apache.ws.axis.security.trust.service;

import java.net.URL;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;

import javax.xml.soap.SOAPHeader;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.utils.ByteArrayOutputStream;
import org.apache.ws.security.trust.STSManager;
import org.apache.ws.security.util.Loader;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

/**
 * @author Ruchith
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class SecurityTokenService {

	protected Hashtable options;
	
	public SecurityTokenService() {
		this.loadProperties("STS.properties");
	}
	
	public void requestSecurityToken(org.apache.ws.axis.security.trust.service.RequestSecurityTokenType request) throws java.rmi.RemoteException{
    	try{
    		MessageContext msgCntxt = MessageContext.getCurrentContext();
	    	msgCntxt.getRequestMessage();
	    	
	        SOAPHeader sHeader = null;
	        //get the request msg    
	        Message smReq = msgCntxt.getRequestMessage();
	        //get the response msg
	       // Message smCurr = msgCntxt.getCurrentMessage();
		   Message smCurr = msgCntxt.getResponseMessage();//.getRequestMessage();
	        //get the request msg as a SOAP part
	        SOAPPart sPartReq = (org.apache.axis.SOAPPart) smReq.getSOAPPart();
	        //get the response msg as a SOAP part
	        SOAPPart sPartRes = (org.apache.axis.SOAPPart) smCurr.getSOAPPart();

	        Document docReq, docRes = null;

	        try {
	            //initialize xml security
	            org.apache.xml.security.Init.init();
	            docReq = ((SOAPEnvelope) sPartReq.getEnvelope()).getAsDocument();
	            docRes = ((SOAPEnvelope) sPartRes.getEnvelope()).getAsDocument();

	            STSManager stsMgr =
	                    new STSManager(this.options);
	            docRes = stsMgr.handleRequest(docReq, docRes);
//	            log.debug("STSServerHandler: STSManager has done the job");
	            ByteArrayOutputStream os = new ByteArrayOutputStream();
	            XMLUtils.outputDOM(docRes, os, true); 
	            //modify the current message
	            sPartRes.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);   
	            //set current message to the context
				//msgCntxt.setCurrentMessage(sPartRes.getMessage());
				//msgCntxt.setPastPivot(true);
				//msgCntxt.setPastPivot(true);
				msgCntxt.setCurrentMessage(sPartRes.getMessage());
	          // msgCntxt.setResponseMessage(sPartRes.getMessage());
			 

	        } catch (Exception ex) {
	            throw new AxisFault("STSServerHandler-dorequest:Response failed due to a problem in issuence process",
	                    ex);
	        }

    	} catch (Exception e) {
    		System.out.println("Exception is "+e.getMessage());
    		throw new AxisFault();
    	}
    }

    protected void loadProperties(String propFilename) {
        Properties properties = new Properties();
        try {
            URL url = Loader.getResource(propFilename);
            properties.load(url.openStream());
        } catch (Exception e) {
            throw new RuntimeException("SecurityTokenSErvice: Cannot load properties: " + propFilename);
        }
        this.options = new Hashtable();
        Enumeration enumKeys = properties.keys();
        while(enumKeys.hasMoreElements()) {
        	String key = (String)enumKeys.nextElement();
        	this.options.put(key,properties.getProperty(key));
        }
    }

}
