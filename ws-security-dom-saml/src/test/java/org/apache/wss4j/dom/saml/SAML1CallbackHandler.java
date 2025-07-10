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

package org.apache.wss4j.dom.saml;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.dom.saml.bean.AdviceBean;
import org.apache.wss4j.dom.saml.bean.KeyInfoBean;
import org.apache.wss4j.dom.saml.bean.SubjectBean;
import org.apache.wss4j.dom.saml.bean.Version;
import org.apache.wss4j.dom.saml.builder.SAML1Constants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;

/**
 * A Callback Handler implementation for a SAML 1.1 assertion. By default it creates an
 * authentication assertion using Sender Vouches.
 */
public class SAML1CallbackHandler extends AbstractSAMLCallbackHandler {

    public SAML1CallbackHandler() throws Exception {
        if (certs == null) {
            Crypto crypto = CryptoFactory.getInstance("wss40.properties");
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("wss40");
            certs = crypto.getX509Certificates(cryptoType);
        }

        subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
        subjectQualifier = "www.example.com";
        confirmationMethod = SAML1Constants.CONF_SENDER_VOUCHES;
        issuer = "www.example.com";
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof SAMLCallback) {
                SAMLCallback samlCallback = (SAMLCallback) callback;
                samlCallback.setSamlVersion(Version.SAML_11);
                samlCallback.setIssuer(issuer);
                if (conditions != null) {
                    samlCallback.setConditions(conditions);
                }
                samlCallback.setIssuerCrypto(getIssuerCrypto());
                samlCallback.setIssuerKeyName(getIssuerName());
                samlCallback.setIssuerKeyPassword(getIssuerPassword());

                if (getAssertionAdviceElement() != null) {
                    AdviceBean advice = new AdviceBean();
                    advice.getAssertions().add(getAssertionAdviceElement());
                    samlCallback.setAdvice(advice);
                }

                SubjectBean subjectBean =
                    new SubjectBean(
                        subjectName, subjectQualifier, confirmationMethod
                    );
                if (subjectNameIDFormat != null) {
                    subjectBean.setSubjectNameIDFormat(subjectNameIDFormat);
                }
                if (SAML1Constants.CONF_HOLDER_KEY.equals(confirmationMethod)) {
                    try {
                        KeyInfoBean keyInfo = createKeyInfo();
                        subjectBean.setKeyInfo(keyInfo);
                    } catch (Exception ex) {
                        throw new IOException("Problem creating KeyInfo: " +  ex.getMessage());
                    }
                }
                createAndSetStatement(subjectBean, samlCallback);
                samlCallback.setSignAssertion(signAssertion);
            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
        }
    }

}
