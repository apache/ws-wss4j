/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.stax.wss.ext;

import org.apache.xml.security.stax.ext.XMLSecurityException;

import javax.xml.namespace.QName;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * class lent from apache wss4j
 */

/**
 * Exception class for WS-Security.
 * todo cleanup and use superclass
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class WSSecurityException extends XMLSecurityException {

    public enum ErrorCode {
        FAILURE,
        UNSUPPORTED_SECURITY_TOKEN,
        UNSUPPORTED_ALGORITHM,
        INVALID_SECURITY,
        INVALID_SECURITY_TOKEN,
        FAILED_AUTHENTICATION,
        FAILED_CHECK,
        SECURITY_TOKEN_UNAVAILABLE,
        MESSAGE_EXPIRED,
        FAILED_ENCRYPTION,
        FAILED_SIGNATURE,
    }

    private static final ResourceBundle resources;
    /*
     * This is an Integer -> QName map. Its function is to map the integer error codes
     * given above to the QName fault codes as defined in the SOAP Message Security 1.1
     * specification. A client application can simply call getFaultCode rather than do
     * any parsing of the error code. Note that there are no mappings for "FAILURE",
     * "FAILED_ENCRYPTION" and "FAILED_SIGNATURE" as these are not standard error messages.
     */
    private static final Map<ErrorCode, QName> FAULT_CODE_MAP = new HashMap<ErrorCode, QName>();

    static {
        try {
            resources = ResourceBundle.getBundle("messages.errors");
        } catch (MissingResourceException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        FAULT_CODE_MAP.put(
                ErrorCode.UNSUPPORTED_SECURITY_TOKEN,
                WSSConstants.UNSUPPORTED_SECURITY_TOKEN
        );
        FAULT_CODE_MAP.put(
                ErrorCode.UNSUPPORTED_ALGORITHM,
                WSSConstants.UNSUPPORTED_ALGORITHM
        );
        FAULT_CODE_MAP.put(
                ErrorCode.INVALID_SECURITY,
                WSSConstants.INVALID_SECURITY
        );
        FAULT_CODE_MAP.put(
                ErrorCode.INVALID_SECURITY_TOKEN,
                WSSConstants.INVALID_SECURITY_TOKEN
        );
        FAULT_CODE_MAP.put(
                ErrorCode.FAILED_AUTHENTICATION,
                WSSConstants.FAILED_AUTHENTICATION
        );
        FAULT_CODE_MAP.put(
                ErrorCode.FAILED_CHECK,
                WSSConstants.FAILED_CHECK
        );
        FAULT_CODE_MAP.put(
                ErrorCode.FAILED_SIGNATURE,
                WSSConstants.FAILED_CHECK
        );
        FAULT_CODE_MAP.put(
                ErrorCode.FAILED_ENCRYPTION,
                WSSConstants.FAILED_CHECK
        );
        FAULT_CODE_MAP.put(
                ErrorCode.SECURITY_TOKEN_UNAVAILABLE,
                WSSConstants.SECURITY_TOKEN_UNAVAILABLE
        );
        FAULT_CODE_MAP.put(
                ErrorCode.MESSAGE_EXPIRED,
                WSSConstants.MESSAGE_EXPIRED
        );
    }

    private ErrorCode errorCode;

    /**
     * Constructor.
     * <p/>
     *
     * @param errorCode
     * @param msgId
     * @param exception
     * @param arguments
     */
    public WSSecurityException(ErrorCode errorCode, String msgId, Throwable exception, Object... arguments) {
        super(getMessage(errorCode, msgId, arguments), exception);
        this.errorCode = errorCode;
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param errorCode
     * @param msgId
     * @param exception
     */
    public WSSecurityException(ErrorCode errorCode, String msgId, Throwable exception) {
        super(getMessage(errorCode, msgId), exception);
        this.errorCode = errorCode;
    }

    public WSSecurityException(ErrorCode errorCode, Throwable exception) {
        super(getMessage(errorCode, null), exception);
        this.errorCode = errorCode;
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param errorCode
     * @param msgId
     * @param arguments
     */
    public WSSecurityException(ErrorCode errorCode, String msgId, Object... arguments) {
        super(getMessage(errorCode, msgId, arguments));
        this.errorCode = errorCode;
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param errorCode
     * @param msgId
     */
    public WSSecurityException(ErrorCode errorCode, String msgId) {
        this(errorCode, msgId, (Object[]) null);
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param errorCode
     */
    public WSSecurityException(ErrorCode errorCode) {
        this(errorCode, null, (Object[]) null);
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param errorMessage
     */
    public WSSecurityException(String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param errorMessage
     */
    public WSSecurityException(String errorMessage, Throwable t) {
        super(errorMessage, t);
    }

    /**
     * Get the error code.
     * <p/>
     *
     * @return error code of this exception See values above.
     */
    public ErrorCode getErrorCode() {
        return this.errorCode;
    }

    /**
     * Get the fault code QName for this associated error code.
     * <p/>
     *
     * @return the fault code QName of this exception
     */
    public javax.xml.namespace.QName getFaultCode() {
        QName ret = FAULT_CODE_MAP.get(this.errorCode);
        if (ret != null) {
            return ret;
        }
        return null;
    }

    /**
     * get the message from resource bundle.
     * <p/>
     *
     * @param errorCode
     * @param msgId
     * @param arguments
     * @return the message translated from the property (message) file.
     */
    private static String getMessage(ErrorCode errorCode, String msgId, Object... arguments) {
        String msg = null;
        try {
            msg = resources.getString(String.valueOf(errorCode.ordinal()));
            if (msgId != null) {
                return msg += (" (" + MessageFormat.format(resources.getString(msgId), arguments) + ")");
            }
        } catch (MissingResourceException e) {
            throw new RuntimeException("Undefined '" + msgId + "' resource property", e);
        }
        return msg;
    }
}