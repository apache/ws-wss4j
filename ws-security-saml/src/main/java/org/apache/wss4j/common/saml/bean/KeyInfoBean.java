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

package org.apache.wss4j.common.saml.bean;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.w3c.dom.Element;


/**
 * Class KeyInfoBean represents a KeyInfo structure that will be embedded in a SAML Subject.
 */
public class KeyInfoBean {

    public enum CERT_IDENTIFIER {
        X509_CERT, X509_ISSUER_SERIAL, KEY_VALUE
    }

    private X509Certificate cert;
    private CERT_IDENTIFIER certIdentifier = CERT_IDENTIFIER.X509_CERT;
    private PublicKey publicKey;
    private byte[] ephemeralKey;
    private Element keyInfoElement;

    /**
     * Constructor KeyInfoBean creates a new KeyInfoBean instance.
     */
    public KeyInfoBean() {
    }

    /**
     * Method getCertificate returns the certificate of this KeyInfoBean object.
     *
     * @return the cert (type X509Certificate) of this KeyInfoBean object.
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /**
     * Method setCertificate sets the cert of this KeyInfoBean object.
     *
     * @param cert the cert of this KeyInfoBean object.
     */
    public void setCertificate(X509Certificate cert) {
        this.cert = cert;
    }

    /**
     * Method getPublicKey returns the public key of this KeyInfoBean object.
     *
     * @return the publicKey (type PublicKey) of this KeyInfoBean object.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Method setPublicKey sets the publicKey of this KeyInfoBean object.
     *
     * @param publicKey the publicKey of this KeyInfoBean object.
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Method getCertIdentifer returns the cert identifer of this KeyInfoBean object.
     *
     * @return the certIdentifier (type CERT_IDENTIFIER) of this KeyInfoBean object.
     */
    public CERT_IDENTIFIER getCertIdentifer() {
        return certIdentifier;
    }

    /**
     * Method setCertIdentifer sets the cert identifier of this KeyInfoBean object.
     *
     * @param certIdentifier the certIdentifier of this KeyInfoBean object.
     */
    public void setCertIdentifer(CERT_IDENTIFIER certIdentifier) {
        this.certIdentifier = certIdentifier;
    }

    public byte[] getEphemeralKey() {
        return ephemeralKey;
    }

    public void setEphemeralKey(byte[] ephemeralKey) {
        this.ephemeralKey = ephemeralKey;
    }

    /**
     * Method getElement returns the DOM Element of this KeyInfoBean object.
     *
     * @return the keyInfoElement (type Element) of this KeyInfoBean object.
     */
    public Element getElement() {
        return keyInfoElement;
    }

    /**
     * Method setElement sets the DOM Element of this KeyInfoBean object.
     *
     * @param keyInfoElement the DOM Element of this KeyInfoBean object.
     */
    public void setElement(Element keyInfoElement) {
        this.keyInfoElement = keyInfoElement;
    }

    /**
     * Method equals ...
     *
     * @param o of type Object
     * @return boolean
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof KeyInfoBean)) {
            return false;
        }

        KeyInfoBean that = (KeyInfoBean) o;

        if (certIdentifier != that.certIdentifier) {
            return false;
        }
        if (cert == null && that.cert != null) {
            return false;
        } else if (cert != null && !cert.equals(that.cert)) {
            return false;
        }

        if (publicKey == null && that.publicKey != null) {
            return false;
        } else if (publicKey != null && !publicKey.equals(that.publicKey)) {
            return false;
        }

        if (keyInfoElement == null && that.keyInfoElement != null) {
            return false;
        } else if (keyInfoElement != null && !keyInfoElement.equals(that.keyInfoElement)) {
            return false;
        }

        return true;
    }

    /**
     * @return the hashCode of this object
     */
    @Override
    public int hashCode() {
        int result = certIdentifier.hashCode();
        if (cert != null) {
            result = 31 * result + cert.hashCode();
        }
        if (publicKey != null) {
            result = 31 * result + publicKey.hashCode();
        }
        if (keyInfoElement != null) {
            result = 31 * result + keyInfoElement.hashCode();
        }
        return result;
    }
}
