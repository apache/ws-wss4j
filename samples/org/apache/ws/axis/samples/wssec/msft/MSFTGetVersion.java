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

package org.apache.ws.axis.samples.wssec.msft;

import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.ws.axis.security.WSDoAllConstants;
import org.apache.ws.axis.security.WSDoAllSender;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.token.UsernameToken;

/**
 * Created by IntelliJ IDEA.
 * User: srida01
 * Date: Nov 5, 2003
 * Time: 4:42:03 PM
 * To change this template use Options | File Templates.
 */
public class MSFTGetVersion {
    static String urlS = "http://ws.microsoft.com/mscomservice/mscom.asmx";

    public static void main(String[] args) throws Exception {
        Service service = new Service();
        Call call = (Call) service.createCall();
        call.setTargetEndpointAddress(new java.net.URL(urlS));
        call.setOperation("GetVersion");
        call.setSOAPActionURI("http://www.microsoft.com/GetVersion");
        call.setUseSOAPAction(true);
        call.setUsername("QDLlbliUmNlNGwIZYSD0mql+eBPV/qU3");
        call.setPassword("WSS4Java");
		call.setProperty(UsernameToken.PASSWORD_TYPE, WSConstants.PASSWORD_DIGEST);
		call.setProperty(WSDoAllConstants.ACTION, WSDoAllConstants.USERNAME_TOKEN);
		call.setClientHandlers(new WSDoAllSender(), null);
        System.out.println((String) call.invoke(new Object[]{}));
    }
}
