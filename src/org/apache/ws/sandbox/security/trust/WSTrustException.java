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
package org.apache.ws.security.trust;

import java.rmi.RemoteException;
import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * @author Malinda Kaushalye
 *
 * Exception class for WS-Trust implementation. 
 */
public class WSTrustException extends RemoteException{
	public static final int PASSWORD_DOESNOT_MATCH = 0;
	private static ResourceBundle resources;
	
	static {
		try {
			resources = ResourceBundle.getBundle("org.apache.ws.security.trust.errors");
		} catch (MissingResourceException e) {
			throw new RuntimeException(e.getMessage());
		}
	}


	/**
	 * 
	 */
	public WSTrustException() {
		super();
	
	}

	/**
	 * @param s
	 */
	public WSTrustException(String s) {
		super(s);
		
	}

	/**
	 * @param s
	 * @param ex
	 */
	public WSTrustException(String s, Throwable ex) {
		super(s, ex);
	
	}
	/**
	 * Constructor
	 * 
	 * @param errorCode
	 */
	public WSTrustException(int errorCode) {
		super(getMessage(errorCode,null,null));
		
	}
	
	private static String getMessage(int errorCode, String msgId, Object[] args) {
		String msg = null;
		try {
			msg = resources.getString(String.valueOf(errorCode));
			if (msgId != null) {
				return msg += (" (" + MessageFormat.format(resources.getString(msgId), args) + ")");
			}
		} catch (MissingResourceException e) {
			throw new RuntimeException("Undefined '" + msgId + "' resource property");
		}
		return msg;
	}

}
