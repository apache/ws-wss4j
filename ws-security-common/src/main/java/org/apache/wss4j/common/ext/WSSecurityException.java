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

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Exception class for WS-Security.
 */
public class WSSecurityException extends XMLSecurityException {

    private static final long serialVersionUID = 4703352039717763655L;


    /****************************************************************************
     * Fault codes defined in the WSS 1.1 spec under section 12, Error handling
     */

    public static final String NS_WSSE10 =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

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

    /**
     * Generic Security error
     */
    public static final QName SECURITY_ERROR =
        new QName("http://ws.apache.org/wss4j", "SecurityError");

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
    public static final String UNIFIED_SECURITY_ERR =
        "A security error was encountered when verifying the message";

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
        SECURITY_ERROR(WSSecurityException.SECURITY_ERROR);

        private QName qName;

        ErrorCode(QName qName) {
            this.qName = qName;
        }

        public QName getQName() {
            return qName;
        }
    }

    /**
     * The WSS4J message bundle, resolved directly rather than through Santuario's I18n.
     * <p/>
     * I18n holds a single static bundle for the whole JVM and both of its init methods return
     * early once it has been set, so whichever library initialises it first owns it for the
     * lifetime of the JVM. WSProviderConfig installs {@code WSS4JResourceBundle}, which knows
     * both WSS4J's message ids and Santuario's, but it only gets the chance if nothing has
     * initialised Santuario before it. When it loses that race - an application that uses XML
     * Signature or OpenSAML before it uses WSS4J, for instance - none of the ids in
     * wss4j_errors.properties resolve any more, and every WSS4J error degrades to
     * 'No message with ID "..." found in resource bundle "..."'.
     * <p/>
     * Resolving our own ids ourselves makes the text independent of who won that race. Ids we
     * do not own are left to I18n, so Santuario's messages keep working as before.
     */
    private static final ResourceBundle WSS4J_MESSAGES = loadMessages();

    private static ResourceBundle loadMessages() {
        try {
            return ResourceBundle.getBundle("messages.wss4j_errors");
        } catch (Exception ex) { //NOPMD
            // Should not happen, the bundle ships with this jar. Deliberately broad: this runs in
            // a static initializer of the exception class every WSS4J failure path goes through,
            // so anything thrown here would surface as an ExceptionInInitializerError in place of
            // the real error. Falling back to I18n is always safe.
            return null;
        }
    }

    /**
     * Format the message for a WSS4J message id, or null if the id is not one of ours, in which
     * case the message that XMLSecurityException already derived via I18n is used instead.
     */
    private static String formatMessage(String msgId, Object... arguments) {
        if (WSS4J_MESSAGES == null || msgId == null) {
            return null;
        }
        try {
            return MessageFormat.format(WSS4J_MESSAGES.getString(msgId), arguments);
        } catch (MissingResourceException ex) { //NOPMD
            // Not a WSS4J message id - it is one of Santuario's, so leave it to I18n
            return null;
        }
    }

    private ErrorCode errorCode;

    /**
     * The message resolved from WSS4J's own bundle, or null when the message id is not one of
     * WSS4J's. Never read directly, see {@link #getMessage()}.
     */
    private final String wss4jMessage;

    public WSSecurityException(ErrorCode errorCode) {
        this(errorCode, errorCode.name());
    }

    public WSSecurityException(ErrorCode errorCode, String msgId) {
        super(msgId, new Object[]{});
        this.errorCode = errorCode;
        this.wss4jMessage = formatMessage(msgId);
    }

    public WSSecurityException(ErrorCode errorCode, Exception exception) {
        super(exception);
        this.errorCode = errorCode;
        // No message id involved, the message is the wrapped exception's own
        this.wss4jMessage = null;
    }

    public WSSecurityException(ErrorCode errorCode, Exception exception, String msgId) {
        super(exception, msgId);
        this.errorCode = errorCode;
        // Mirrors I18n.getExceptionMessage(String, Exception), which formats the wrapped
        // exception's message as the single argument
        this.wss4jMessage = formatMessage(msgId, exception.getMessage());
    }

    public WSSecurityException(ErrorCode errorCode, Exception exception, String msgId, Object[] arguments) {
        super(exception, msgId, arguments);
        this.errorCode = errorCode;
        this.wss4jMessage = formatMessage(msgId, arguments);
    }

    public WSSecurityException(ErrorCode errorCode, String msgId, Object[] arguments) {
        super(msgId, arguments);
        this.errorCode = errorCode;
        this.wss4jMessage = formatMessage(msgId, arguments);
    }

    @Override
    public String getMessage() {
        return wss4jMessage != null ? wss4jMessage : super.getMessage();
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
     * Get a "safe" / unified error message, so as not to leak internal configuration
     * to an attacker.
     */
    public String getSafeExceptionMessage() {
        return UNIFIED_SECURITY_ERR;

    }

    /**
     * Get the "safe" / unified fault code QName associated with this exception, so as
     * not to leak internal configuration to an attacker
     */
    public QName getSafeFaultCode() {
        return SECURITY_ERROR;
    }
}
