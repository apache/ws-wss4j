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

package org.apache.ws.sandbox.axis.security.trust;


import org.apache.axis.message.addressing.Action;
import org.apache.axis.message.addressing.Address;
import org.apache.axis.message.addressing.AddressingHeaders;
import org.apache.axis.message.addressing.EndpointReference;
import org.apache.axis.types.URI;
import org.apache.axis.types.URI.MalformedURIException;

/**
 * This is used to provide the addressing headers required by the STSAgent 
 * @author Ruchith
 */
public class STSAgentAddressingConfiguration {

	private AddressingHeaders headers = new AddressingHeaders();
	
	/**
	 * Set the action URI
	 * @param actionUri 
	 * @throws MalformedURIException
	 */
	public void setAction(String actionUri) throws MalformedURIException {
		Action a = new Action(new URI(actionUri));
		this.headers.setAction(a);
	}
	/**
	 * SEt the from EPR
	 * @param endpoint
	 * @throws MalformedURIException
	 */
	public void setFrom(String endpoint) throws MalformedURIException {
		this.headers.setFrom(new EndpointReference(endpoint));
	}
	
	/**
	 * Set the from EPR
	 * @param endpoint
	 * @throws MalformedURIException
	 */
	public void setFaultTo(String endpoint) throws MalformedURIException {
		this.headers.setFaultTo(new EndpointReference(endpoint));
	}
	
	/**
	 * Return the configured addressing headers
	 * @return
	 */
	public AddressingHeaders getHeaders() {
		return this.headers;
	}
	
	public void setRepyTo(String endpoint) throws MalformedURIException {
		//this.headers.setReplyTo(new Address(endpoint));
	}
}