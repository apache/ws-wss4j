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

package org.apache.ws.security;

import java.security.Principal;
import java.security.cert.X509Certificate;


/**
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class WSSecurityEngineResult {
	
	private int action;
	private Principal principal;
	private X509Certificate cert;

	WSSecurityEngineResult(
		Principal princ,
		int act,
		X509Certificate certificate) {
		principal = princ;
		action = act;
		cert = certificate;
	}
	/**
	 * @return the actions vector. These actions were performed
	 * by the the security engine.
	 */
	public int getAction() {
		return action;
	}

	/**
	 * @return the principals found if UsernameToken or Signature
	 * processing were done
	 */
	public Principal getPrincipal() {
		return principal;
	}
	/**
	 * @return the Certificate found if Signature
	 * processing were done
	 */
	public X509Certificate getCertificate() {
		return cert;
	}

}
