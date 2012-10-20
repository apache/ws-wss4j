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

package org.apache.ws.security.stax.test.saml;

import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.crypto.CryptoFactory;
import org.apache.ws.security.common.crypto.CryptoType;
import org.apache.ws.security.common.saml.SAMLCallback;
import org.apache.ws.security.common.saml.bean.KeyInfoBean;
import org.apache.ws.security.common.saml.bean.SubjectBean;
import org.apache.ws.security.common.saml.builder.SAML2Constants;
import org.opensaml.common.SAMLVersion;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * A Callback Handler implementation for a SAML 2 assertion. By default it creates an
 * authentication assertion using Sender Vouches.
 */
public class SAML2CallbackHandler extends AbstractSAMLCallbackHandler {

    public SAML2CallbackHandler() throws Exception {
        if (certs == null) {
            Crypto crypto = CryptoFactory.getInstance("saml/saml-signed.properties");
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            certs = crypto.getX509Certificates(cryptoType);
            issuerKeyName = "samlissuer";
            issuerKeyPassword = "default";
            issuerCrypto = CryptoFactory.getInstance("saml/samlissuer.properties");
        }

        subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
        subjectQualifier = "www.example.com";
        confirmationMethod = SAML2Constants.CONF_SENDER_VOUCHES;
        issuer = "www.example.com";
    }

    @Override
    public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                SAMLCallback callback = (SAMLCallback) callbacks[i];
                callback.setSamlVersion(SAMLVersion.VERSION_20);
                callback.setIssuer(issuer);
                callback.setIssuerKeyName(issuerKeyName);
                callback.setIssuerKeyPassword(issuerKeyPassword);
                callback.setIssuerCrypto(issuerCrypto);
                callback.setSignAssertion(signAssertion);
                if (conditions != null) {
                    callback.setConditions(conditions);
                }

                SubjectBean subjectBean =
                        new SubjectBean(
                                subjectName, subjectQualifier, confirmationMethod
                        );
                if (subjectNameIDFormat != null) {
                    subjectBean.setSubjectNameIDFormat(subjectNameIDFormat);
                }
                if (SAML2Constants.CONF_HOLDER_KEY.equals(confirmationMethod)) {
                    try {
                        KeyInfoBean keyInfo = createKeyInfo();
                        subjectBean.setKeyInfo(keyInfo);
                    } catch (Exception ex) {
                        throw new IOException("Problem creating KeyInfo: " + ex.getMessage());
                    }
                }
                callback.setSubject(subjectBean);
                createAndSetStatement(null, callback);
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

}
