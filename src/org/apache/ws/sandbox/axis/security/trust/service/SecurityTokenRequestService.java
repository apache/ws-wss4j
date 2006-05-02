/**
 * SecurityTokenRequestService.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis #axisVersion# #today# WSDL2Java emitter.
 */

package org.apache.ws.sandbox.axis.security.trust.service;

import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;


public class SecurityTokenRequestService {
    public void requestSecurityToken(org.apache.ws.sandbox.axis.security.trust.service.RequestSecurityTokenType request) throws java.rmi.RemoteException{
              MessageContext context = MessageContext.getCurrentContext();
              
//              try {
//                context.setResponseMessage(getSOAPMessage());
//            } catch (Exception e) {
//                System.out.println(e.getMessage());
//                e.printStackTrace();
//            }
    }
    
	protected Message getSOAPMessage() throws Exception {
		   InputStream in = new FileInputStream("response.xml");
		   Message msg = new Message(in);
		   return msg;
	   }
}
