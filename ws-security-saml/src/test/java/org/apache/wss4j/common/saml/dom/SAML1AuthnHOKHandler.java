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

package org.apache.wss4j.common.saml.dom;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML1Constants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * A Callback Handler implementation for a SAML 1.1 authentication assertion using
 * Holder of Key.
 */
public class SAML1AuthnHOKHandler implements CallbackHandler {

    private String subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
    private String subjectQualifier = "www.example.com";
    private X509Certificate[] certs;

    public SAML1AuthnHOKHandler() throws WSSecurityException {
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        certs = crypto.getX509Certificates(cryptoType);
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof SAMLCallback) {
                SAMLCallback samlCallback = (SAMLCallback) callback;
                samlCallback.setSamlVersion(Version.SAML_11);
                SubjectBean subjectBean =
                    new SubjectBean(
                        subjectName, subjectQualifier, SAML1Constants.CONF_HOLDER_KEY
                    );
                KeyInfoBean keyInfo = new KeyInfoBean();
                keyInfo.setCertificate(certs[0]);
                subjectBean.setKeyInfo(keyInfo);
                AuthenticationStatementBean authBean = new AuthenticationStatementBean();
                authBean.setSubject(subjectBean);
                authBean.setAuthenticationMethod("Password");
                samlCallback.setAuthenticationStatementData(Collections.singletonList(authBean));
            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
        }
    }
}
