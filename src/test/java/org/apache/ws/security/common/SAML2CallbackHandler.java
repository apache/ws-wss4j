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

package org.apache.ws.security.common;

import org.apache.ws.security.saml.ext.SAMLCallback;
import org.apache.ws.security.saml.ext.bean.ActionBean;
import org.apache.ws.security.saml.ext.bean.AttributeBean;
import org.apache.ws.security.saml.ext.bean.AttributeStatementBean;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.AuthDecisionStatementBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.Collections;

/**
 * A Callback Handler implementation for a SAML 2 assertion. By default it creates an
 * authentication assertion using Sender Vouches.
 */
public class SAML2CallbackHandler implements CallbackHandler {
    
    public enum Statement {
        AUTHN, ATTR, AUTHZ
    };
    
    private String subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
    private String subjectQualifier = "www.example.com";
    private String confirmationMethod = SAML2Constants.CONF_SENDER_VOUCHES;
    private Statement statement = Statement.AUTHN;
    
    public SAML2CallbackHandler() {
    }
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                SAMLCallback callback = (SAMLCallback) callbacks[i];
                SubjectBean subjectBean = 
                    new SubjectBean(
                        subjectName, subjectQualifier, confirmationMethod
                    );
                callback.setSubject(subjectBean);
                createAndSetStatement(subjectBean, callback);
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
    
    public void setConfirmationMethod(String confMethod) {
        confirmationMethod = confMethod;
    }
    
    public void setStatement(Statement statement) {
        this.statement = statement;
    }
    
    private void createAndSetStatement(SubjectBean subjectBean, SAMLCallback callback) {
        if (statement == Statement.AUTHN) {
            AuthenticationStatementBean authBean = new AuthenticationStatementBean();
            authBean.setAuthenticationMethod("Password");
            callback.setAuthenticationStatementData(Collections.singletonList(authBean));
        } else if (statement == Statement.ATTR) {
            AttributeStatementBean attrBean = new AttributeStatementBean();
            AttributeBean attributeBean = new AttributeBean();
            attributeBean.setSimpleName("role");
            attributeBean.setAttributeValues(Collections.singletonList("user"));
            attrBean.setSamlAttributes(Collections.singletonList(attributeBean));
            callback.setAttributeStatementData(Collections.singletonList(attrBean));
        } else {
            AuthDecisionStatementBean authzBean = new AuthDecisionStatementBean();
            ActionBean actionBean = new ActionBean();
            actionBean.setContents("Read");
            authzBean.setActions(Collections.singletonList(actionBean));
            authzBean.setResource("endpoint");
            authzBean.setDecision(AuthDecisionStatementBean.Decision.PERMIT);
            callback.setAuthDecisionStatementData(Collections.singletonList(authzBean));
        }
    }
}
