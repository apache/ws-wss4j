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
 *         <p/>
 *         Exception class for WS-Trust implementation.
 */
public class WSTrustException extends RemoteException {	
	
	public static final String INVALID_REQUEST = "InvalidRequest";
    
    
    private static ResourceBundle resources;

    private String faultCode;
    private String faultString;
    
    static {
        try {
            resources = ResourceBundle.getBundle("org.apache.ws.security.trust.errors");
        } catch (MissingResourceException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public WSTrustException(String faultCode, String msgId, Object[] args, Throwable exception) {
        super(getMessage(faultCode, null, null),exception);
        this.faultCode = faultCode;
        this.faultString = resources.getString(faultCode);
    }

    public WSTrustException(String faultCode, String msgId, Object[] args) {
        super(getMessage(faultCode, null, null));
        this.faultCode = faultCode;
        this.faultString = resources.getString(faultCode);
    }

    private static String getMessage(String faultCode, String msgId, Object[] args) {
        String msg = null;
        try {
            msg = resources.getString(faultCode);
            if (msgId != null) {
                return msg += (" (" + MessageFormat.format(resources.getString(msgId), args) + ")");
            }
        } catch (MissingResourceException e) {
            throw new RuntimeException("Undefined '" + msgId + "' resource property");
        }
        return msg;
    }

    public WSTrustException(String message) {
    	super(message);    	
    }
    
    public WSTrustException(String message, Throwable ex) {
    	super(message,ex);    	
    }
    
    
    /**
     * Return the fault code
     * @return
     */
	public String getFaultCode() {
		return TrustConstants.WST_PREFIX + faultCode;
	}
	
	/**
	 * Return the fault string
	 * @return
	 */
	public String getFaultString() {
		return faultString;
	}
}
