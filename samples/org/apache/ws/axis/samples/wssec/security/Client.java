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

package org.apache.ws.axis.samples.wssec.security;

import org.apache.axis.MessageContext;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.message.SOAPBodyElement;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.utils.Options;
import org.apache.axis.utils.XMLUtils;
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSignEnvelope;
import org.w3c.dom.Document;

/**
 * Sample Client
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class Client {
    /** Instance of the Security Engine */
    static final WSSecurityEngine secEngine = new WSSecurityEngine();

    /**
     * Create a Call object by hand and sign the SOAP Message as well
     * <p/>
     * 
     * @param args command line parameters
     * @throws Exception Thrown when there are any problems
     */
    public static void main(String[] args) throws Exception {
        Options opts = new Options(args);
        Service service = new Service();
        Call call = (Call) service.createCall();
        call.setTargetEndpointAddress(new java.net.URL(opts.getURL()));
        SOAPEnvelope env = new SOAPEnvelope();
        SOAPBodyElement sbe = new SOAPBodyElement(XMLUtils.StringToElement("http://localhost:8080/LogTestService", "testMethod", ""));
        env.addBodyElement(sbe);
        Document doc = null;
        if (opts.isFlagSet('x') > 0) {
            WSSignEnvelope builder = new WSSignEnvelope();
            doc = builder.build(env.getAsDocument(), CryptoFactory.getInstance());
        }
        System.out.println("\n============= Request ==============");
        System.out.println(org.apache.axis.utils.XMLUtils.DocumentToString(doc));
        env = (org.apache.axis.message.SOAPEnvelope) AxisUtil.toSOAPMessage(doc).getSOAPPart().getEnvelope();
        call.invoke(env);
        MessageContext mc = call.getMessageContext();
        System.out.println("\n============= Response ==============");
        XMLUtils.PrettyElementToStream(mc.getResponseMessage().getSOAPEnvelope().getAsDOM(), System.out);
    }
}
