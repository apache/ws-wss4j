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

package org.swssf.xmlsec.crypto;

import org.swssf.xmlsec.ext.XMLSecurityException;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * class lent from apache wss4j
 */

/**
 * Crypto.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public interface Crypto {
    /**
     * load a X509Certificate from the input stream.
     * <p/>
     *
     * @param in The <code>InputStream</code> array containing the X509 data
     * @return An X509 certificate
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    X509Certificate loadCertificate(InputStream in) throws XMLSecurityException;

    /**
     * Construct an array of X509Certificate's from the byte array.
     * <p/>
     *
     * @param data    The <code>byte</code> array containing the X509 data
     * @param reverse If set the first certificate in input data will
     *                the last in the array
     * @return An array of X509 certificates, ordered according to
     *         the reverse flag
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    X509Certificate[] getX509Certificates(byte[] data, boolean reverse) throws XMLSecurityException;

    /**
     * Gets the private key identified by <code>alias</> and <code>password</code>.
     * <p/>
     *
     * @param alias    The alias (<code>KeyStore</code>) of the key owner
     * @param password The password needed to access the private key
     * @return The private key
     * @throws Exception
     */
    public PrivateKey getPrivateKey(String alias, String password) throws XMLSecurityException;

    /**
     * get the list of certificates for a given alias. This method
     * reads a new certificate chain and overwrites a previously
     * stored certificate chain.
     * <p/>
     *
     * @param alias Lookup certificate chain for this alias
     * @return Array of X509 certificates for this alias name, or
     *         null if this alias does not exist in the keystore
     */
    public X509Certificate[] getCertificates(String alias) throws XMLSecurityException;

    /**
     * Return a X509 Certificate alias in the keystore according to a given Certificate
     * <p/>
     *
     * @param cert The certificate to lookup
     * @return alias name of the certificate that matches the given certificate
     *         or null if no such certificate was found.
     *         <p/>
     *         See comment above
     *         <p/>
     *         See comment above
     */
    /*
     * See comment above
     */
    public String getAliasForX509Cert(Certificate cert) throws XMLSecurityException;

    /**
     * Search a X509 Certificate in the keystore according to a given serial number and
     * the issuer of a Certificate.
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate chain
     * for each alias. Then the SerialNumber and Issuer of each certificate of the chain
     * is compared with the parameters.
     *
     * @param issuer       The issuer's name for the certificate
     * @param serialNumber The serial number of the certificate from the named issuer
     * @return alias name of the certificate that matches serialNumber and issuer name
     *         or null if no such certificate was found.
     */
    public String getAliasForX509Cert(String issuer, BigInteger serialNumber) throws XMLSecurityException;

    /**
     * Search a X509 Certificate in the keystore according to a given serial number and
     * the issuer of a Certificate.
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate chain
     * for each alias. Then the SerialNumber and Issuer of each certificate of the chain
     * is compared with the parameters.
     *
     * @param issuer       The issuer's name for the certificate
     * @param serialNumber The serial number of the certificate from the named issuer
     * @return alias name of the certificate that matches serialNumber and issuer name
     *         or null if no such certificate was found.
     */
    public X509Certificate[] getCertificates(String issuer, BigInteger serialNumber) throws XMLSecurityException;

    /**
     * Lookup a X509 Certificate in the keystore according to a given
     * SubjectKeyIdentifier.
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate chain
     * or certificate for each alias. Then the SKI for each user certificate
     * is compared with the SKI parameter.
     *
     * @param skiBytes The SKI info bytes
     * @return alias name of the certificate that matches serialNumber and issuer name
     *         or null if no such certificate was found.
     */
    public String getAliasForX509Cert(byte[] skiBytes) throws XMLSecurityException;

    /**
     * Retrieves the alias name of the default certificate which has been
     * specified as a property. This should be the certificate that is used for
     * signature and encryption. This alias corresponds to the certificate that
     * should be used whenever KeyInfo is not present in a signed or
     * an encrypted message. May return null.
     *
     * @return alias name of the default X509 certificate.
     */
    public String getDefaultX509Alias();

    /**
     * Reads the SubjectKeyIdentifier information from the certificate.
     * <p/>
     *
     * @param cert The certificate to read SKI
     * @return The byte array containing the binary SKI data
     */
    public byte[] getSKIBytesFromCert(X509Certificate cert) throws XMLSecurityException;

    /**
     * Lookup a X509 Certificate in the keystore according to a given
     * Thumbprint.
     * <p/>
     * The search gets all alias names of the keystore, then reads the certificate chain
     * or certificate for each alias. Then the thumbprint for each user certificate
     * is compared with the thumbprint parameter.
     *
     * @param thumb The SHA1 thumbprint info bytes
     * @return alias name of the certificate that matches the thumbprint
     *         or null if no such certificate was found.
     * @throws org.swssf.ext.XMLSecurityException
     *          if problems during keystore handling or wrong certificate
     */

    public String getAliasForX509CertThumb(byte[] thumb) throws XMLSecurityException;

    /**
     * Gets the CertificateFactory instantiated by the underlying implementation
     *
     * @return the CertificateFactory
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    public CertificateFactory getCertificateFactory() throws XMLSecurityException;

    /**
     * Evaluate whether a given certificate chain should be trusted.
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    public boolean verifyTrust(X509Certificate[] certs) throws XMLSecurityException;

    /**
     * Evaluate whether a given public key should be trusted.
     *
     * @param publicKey The PublicKey to be evaluated
     * @return whether the PublicKey parameter is trusted or not
     */
    public boolean verifyTrust(PublicKey publicKey) throws XMLSecurityException;
}
