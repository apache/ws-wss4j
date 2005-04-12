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

import javax.xml.soap.SOAPHeader;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.utils.ByteArrayOutputStream;
import org.apache.ws.axis.security.trust.service.SecurityTokenService;
import org.apache.ws.security.trust.STSManager;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

/**
 * @author Ruchith Fernando
 */
public class SecurityContextTokenService extends SecurityTokenService {

    public SecurityContextTokenService() {
        this.loadProperties("SCTS.properties");
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
//              log.debug("STSServerHandler: STSManager has done the job");
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
}
