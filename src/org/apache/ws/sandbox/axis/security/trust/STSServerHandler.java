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

import java.io.ByteArrayOutputStream;

import javax.xml.soap.SOAPHeader;

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.handlers.BasicHandler;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.ws.security.trust.STSManager;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/**
 * @author Malinda Kaushalye
 * 
 * 
 * <code>STSServerHandler</code> is a handler which resides in the response path
 * of the Security Token Service end.
 * <code>STSServerHandler</code> currently performs following tasks
 *    <ul>
 *    <li>
 *            Get the request from the message context
 *    </li>
 *     <li>
 *            Create an <code>STSManager</code> and handover the task to be carried out.
 *    </li>
 *     <li>
 *            Get the resulted SOAP enevelop from <code>STSManager</code> 
 *    </li>
 *     <li>
 *            Set the current message of the message context 
 *    </li>
 *
 *    </ul>
 *
 */
public class STSServerHandler extends BasicHandler {
    
    static Log log = LogFactory.getLog(STSServerHandler.class.getName());
    public STSServerHandler() {
            
    }
    /**
     *  Invoke method of handler
     *   
     */
    public void invoke(MessageContext msgCntxt) throws AxisFault {
        log.debug("STSServerHandler: invoked");

        if (msgCntxt.getPastPivot()) {
            doRequest(msgCntxt);
        } else {
            
        }
        
    }
    /**
     * Processing the outgoing msg
     * 
     * @param msgCntxt
     * @throws AxisFault
     */
    private void doRequest(MessageContext msgCntxt) throws AxisFault {
        log.debug("STSServerHandler: doRequest");
        SOAPHeader sHeader = null;
        //get the request msg    
        Message smReq = msgCntxt.getRequestMessage();
        //get the response msg
        Message smCurr = msgCntxt.getCurrentMessage();
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

            ByteArrayOutputStream osReq = new ByteArrayOutputStream();
            XMLUtils.outputDOM(docReq, osReq, true);

            ByteArrayOutputStream osRes = new ByteArrayOutputStream();
            XMLUtils.outputDOM(docRes, osRes, true);
            
            //creates an STSManager and handover server-config.wsdd parameters in a hash table
            log.debug("STSServerHandler: calling STSManager");
            STSManager stsMgr =
                new STSManager(this.getOptions());
            docRes = stsMgr.handleRequest(docReq, docRes);
            log.debug("STSServerHandler: STSManager has done the job");
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(docRes, os, true); 
            //modify the current message
            sPartRes.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);            
            //set current message to the context
            msgCntxt.setCurrentMessage(sPartRes.getMessage());
            
        } catch (Exception ex) {
            throw new AxisFault(
                "STSServerHandler-dorequest:Response failed due to a problem in issuence process",
                ex);
        }        
        

    }
    
        


}
