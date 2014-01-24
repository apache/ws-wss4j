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

package org.apache.wss4j.common.ext;

import org.apache.xml.security.exceptions.XMLSecurityException;

import javax.xml.namespace.QName;

/**
 * Exception class for WS-Security.
 */
public class WSSecurityException extends XMLSecurityException {
    
    private static final long serialVersionUID = 4703352039717763655L;
    

    /****************************************************************************
     * Fault codes defined in the WSS 1.1 spec under section 12, Error handling
     */
    
    public static final String NS_WSSE10 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

    /**
     * An unsupported token was provided
     */
    public static final QName UNSUPPORTED_SECURITY_TOKEN = new QName(NS_WSSE10, "UnsupportedSecurityToken");

    /**
     * An unsupported signature or encryption algorithm was used
     */
    public static final QName UNSUPPORTED_ALGORITHM = new QName(NS_WSSE10, "UnsupportedAlgorithm");

    /**
     * An error was discovered processing the <Security> header
     */
    public static final QName INVALID_SECURITY = new QName(NS_WSSE10, "InvalidSecurity");

    /**
     * An invalid security token was provided
     */
    public static final QName INVALID_SECURITY_TOKEN = new QName(NS_WSSE10, "InvalidSecurityToken");

    /**
     * The security token could not be authenticated or authorized
     */
    public static final QName FAILED_AUTHENTICATION = new QName(NS_WSSE10, "FailedAuthentication");

    /**
     * The signature or decryption was invalid
     */
    public static final QName FAILED_CHECK = new QName(NS_WSSE10, "FailedCheck");

    /**
     * Referenced security token could not be retrieved
     */
    public static final QName SECURITY_TOKEN_UNAVAILABLE = new QName(NS_WSSE10, "SecurityTokenUnavailable");

    /**
     * The message has expired
     */
    public static final QName MESSAGE_EXPIRED = new QName(NS_WSSE10, "MessageExpired");
    
    // FAULT error messages
    public static final String UNSUPPORTED_TOKEN_ERR = "An unsupported token was provided";
    public static final String UNSUPPORTED_ALGORITHM_ERR = 
        "An unsupported signature or encryption algorithm was used";
    public static final String INVALID_SECURITY_ERR = 
        "An error was discovered processing the <wsse:Security> header.";
    public static final String INVALID_SECURITY_TOKEN_ERR = 
        "An invalid security token was provided";
    public static final String FAILED_AUTHENTICATION_ERR = 
        "The security token could not be authenticated or authorized";
    public static final String FAILED_CHECK_ERR = "The signature or decryption was invalid";
    public static final String SECURITY_TOKEN_UNAVAILABLE_ERR = 
        "Referenced security token could not be retrieved";
    public static final String MESSAGE_EXPIRED_ERR = "The message has expired";

    public enum ErrorCode {
        FAILURE(null), //Non standard error message
        UNSUPPORTED_SECURITY_TOKEN(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN),
        UNSUPPORTED_ALGORITHM(WSSecurityException.UNSUPPORTED_ALGORITHM),
        INVALID_SECURITY(WSSecurityException.INVALID_SECURITY),
        INVALID_SECURITY_TOKEN(WSSecurityException.INVALID_SECURITY_TOKEN),
        FAILED_AUTHENTICATION(WSSecurityException.FAILED_AUTHENTICATION),
        FAILED_CHECK(WSSecurityException.FAILED_CHECK),
        SECURITY_TOKEN_UNAVAILABLE(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE),
        MESSAGE_EXPIRED(WSSecurityException.MESSAGE_EXPIRED),
        FAILED_ENCRYPTION(null), //Non standard error message
        FAILED_SIGNATURE(null), //Non standard error message
        ;

        private QName qName;

        private ErrorCode(QName qName) {
            this.qName = qName;
        }

        public QName getQName() {
            return qName;
        }
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
    public WSSecurityException(ErrorCode errorCode, String msgId, Exception exception, Object... arguments) {
        super(msgId, arguments, exception);
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
    public WSSecurityException(ErrorCode errorCode, String msgId, Exception exception) {
        super(msgId, exception);
        this.errorCode = errorCode;
    }

    public WSSecurityException(ErrorCode errorCode, Exception exception) {
        super(exception);
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
        super(msgId, arguments);
        this.errorCode = errorCode;
    }


    /**
     * Constructor.
     * <p/>
     *
     * @param errorCode
     */
    public WSSecurityException(ErrorCode errorCode) {
        this(errorCode, errorCode.name());
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
    public QName getFaultCode() {
        return this.errorCode.getQName();
    }
    
    /**
     * Map a WSSecurityException FaultCode to a standard error String, so as not to leak
     * internal configuration to an attacker.
     */
    public String getSafeExceptionMessage() {
        // Allow a Replay Attack message to be returned, otherwise it could be confusing
        // for clients who don't understand the default caching functionality of WSS4J/CXF
        if (getMessage() != null && getMessage().contains("replay attack")) {
            return getMessage();
        }
        
        String errorMessage = null;
        QName faultCode = getFaultCode();
        if (UNSUPPORTED_SECURITY_TOKEN.equals(faultCode)) {
            errorMessage = UNSUPPORTED_TOKEN_ERR;
        } else if (UNSUPPORTED_ALGORITHM.equals(faultCode)) {
            errorMessage = UNSUPPORTED_ALGORITHM_ERR;
        } else if (INVALID_SECURITY.equals(faultCode)) {
            errorMessage = INVALID_SECURITY_ERR;
        } else if (INVALID_SECURITY_TOKEN.equals(faultCode)) {
            errorMessage = INVALID_SECURITY_TOKEN_ERR;
        } else if (FAILED_AUTHENTICATION.equals(faultCode)) {
            errorMessage = FAILED_AUTHENTICATION_ERR;
        } else if (FAILED_CHECK.equals(faultCode)) {
            errorMessage = FAILED_CHECK_ERR;
        } else if (SECURITY_TOKEN_UNAVAILABLE.equals(faultCode)) {
            errorMessage = SECURITY_TOKEN_UNAVAILABLE_ERR;
        } else if (MESSAGE_EXPIRED.equals(faultCode)) {
            errorMessage = MESSAGE_EXPIRED_ERR;
        } else {
            // Default
            errorMessage = INVALID_SECURITY_ERR;
        }
        return errorMessage;
        
    }
}