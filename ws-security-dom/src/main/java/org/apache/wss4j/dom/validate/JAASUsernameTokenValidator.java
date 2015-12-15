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

package org.apache.wss4j.dom.validate;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.NamePasswordCallbackHandler;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;


/**
 * This class validates a processed UsernameToken, extracted from the Credential passed to
 * the validate method.
 * Username/password validation is delegated to JAAS LoginContext.
 */
public class JAASUsernameTokenValidator implements Validator {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(JAASUsernameTokenValidator.class);

    private String contextName;

    public void setContextName(String name) {
        contextName = name;
    }

    public String getContextName() {
        return contextName;
    }

    /**
     * Validate the credential argument. It must contain a non-null UsernameToken. A
     * CallbackHandler implementation is also required to be set.
     * Validator
     * If the password type is either digest or plaintext, it extracts a password from the
     * CallbackHandler and then compares the passwords appropriately.
     *
     * If the password is null it queries a hook to allow the user to validate UsernameTokens
     * of this type.
     *
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getUsernametoken() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCredential");
        }

        String user = null;
        String password = null;

        UsernameToken usernameToken = credential.getUsernametoken();

        user = usernameToken.getName();
        String pwType = usernameToken.getPasswordType();
        if (LOG.isDebugEnabled()) {
            LOG.debug("UsernameToken user " + usernameToken.getName());
            LOG.debug("UsernameToken password type " + pwType);
        }

        if (usernameToken.isHashed()) {
            LOG.warn("Authentication failed as hashed username token not supported");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        password = usernameToken.getPassword();

        if (!WSConstants.PASSWORD_TEXT.equals(pwType)) {
            LOG.warn("Password type " + pwType + " not supported");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);        	
        }

        if (!(user != null && user.length() > 0 && password != null && password.length() > 0)) {
            LOG.warn("User or password empty");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        try {
            CallbackHandler handler = getCallbackHandler(user, password);
            LoginContext ctx = new LoginContext(getContextName(), handler);
            ctx.login();
            Subject subject = ctx.getSubject();
            credential.setSubject(subject);

        } catch (LoginException ex) {
            LOG.info("Authentication failed", ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, ex
            );
        }

        return credential;

    }

    protected CallbackHandler getCallbackHandler(String name, String password) {
        return new NamePasswordCallbackHandler(name, password);
    }

}
