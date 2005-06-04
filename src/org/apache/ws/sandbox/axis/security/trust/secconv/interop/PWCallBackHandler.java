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


/*
 * Created on Aug 27, 2004
 *
 */
package org.apache.ws.axis.security.trust.secconv.interop;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.ws.security.WSPasswordCallback;

/**
 * @author Dimuthu
 *
 */
public class PWCallBackHandler implements CallbackHandler {
	
		public void handle(Callback[] callbacks)
			throws IOException, UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof WSPasswordCallback) {
					WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
					//for whatever username set the password as rabbit
					if(pc.getIdentifer().equals("Alice")){						
						pc.setPassword("ecilA");
					} else if(pc.getIdentifer().equals("alice")) {
						pc.setPassword("password");
					} else if(pc.getIdentifer().equals("bob")) {
						pc.setPassword("password");
					}
			     }
			}
		}//handler
		
		
	}
	


