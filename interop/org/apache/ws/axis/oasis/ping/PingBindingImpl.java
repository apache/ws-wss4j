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

/**
 * PingBindingImpl.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.2dev Oct 27, 2003 (02:34:09 EST) WSDL2Java emitter.
 */

package org.apache.ws.axis.oasis.ping;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.ws.axis.security.WSDoAllConstants;
import org.apache.ws.axis.security.WSDoAllReceiverResult;
import org.apache.ws.security.WSConstants;

import java.security.Principal;
import java.util.Vector;

public class PingBindingImpl
	implements org.apache.ws.axis.oasis.ping.PingPort {
	public void ping(
		javax.xml.rpc.holders.StringHolder text,
		org.apache.ws.axis.oasis.ping.TicketType ticket)
		throws java.rmi.RemoteException {
		// text.value = "Echo " + text.value.trim();
		text.value = "Echo " + text.value;
		MessageContext msgContext = MessageContext.getCurrentContext();
		Message reqMsg = msgContext.getRequestMessage();

		Vector results = null;
		if ((results =
			(Vector) msgContext.getProperty(WSDoAllConstants.RECV_RESULTS))
			== null) {
			System.out.println("No security results!!");
		}
		System.out.println("Number of results: " + results.size());
		for (int i = 0; i < results.size(); i++) {
			WSDoAllReceiverResult rResult =
				(WSDoAllReceiverResult) results.get(i);
			Vector principals = rResult.getPrincipals();
			Vector actions = rResult.getActions();

			for (int j = 0; j < principals.size(); j++) {
				if (((Integer) actions.get(j)).intValue()
					!= WSConstants.ENCR) {
					System.out.println(
						((Principal) principals.get(j)).getName());
				}
			}
		}
	}

}
