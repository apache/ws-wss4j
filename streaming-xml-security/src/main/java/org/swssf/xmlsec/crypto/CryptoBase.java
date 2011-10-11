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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.xmlsec.config.ConfigurationProperties;
import org.swssf.xmlsec.ext.XMLSecurityException;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * class lent from apache wss4j
 */

/**
 * Created by IntelliJ IDEA.
 * User: dims
 * Date: Sep 15, 2005
 * Time: 9:50:40 AM
 * To change this template use File | Settings | File Templates.
 */
public abstract class CryptoBase implements Crypto {
    private static Log log = LogFactory.getLog(CryptoBase.class);
    private static final Constructor<?> BC_509CLASS_CONS;


    protected static Map<String, CertificateFactory> certFactMap = new HashMap<String, CertificateFactory>();
    protected KeyStore keystore = null;
    static String SKI_OID = "2.5.29.14";
    protected static KeyStore cacerts = null;
    /**
     * OID For the NameConstraints Extension to X.509
     * <p/>
     * http://java.sun.com/j2se/1.4.2/docs/api/
     * http://www.ietf.org/rfc/rfc3280.txt (s. 4.2.1.11)
     */
    public static final String NAME_CONSTRAINTS_OID = "2.5.29.30";

    static {
        Constructor<?> cons = null;
        try {
            Class<?> c = Class.forName("org.bouncycastle.asn1.x509.X509Name");
            cons = c.getConstructor(new Class[]{String.class});
        } catch (Exception e) {
            //ignore
        }
        BC_509CLASS_CONS = cons;
    }


    /**
     * Constructor
     */
    protected CryptoBase() {
        if (cacerts == null) {
            InputStream cacertsIs = null;

            try {
                String cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
                cacertsIs = new FileInputStream(cacertsPath);
                String cacertsPasswd = ConfigurationProperties.getProperty("CACertKeyStorePassword");

                cacerts = KeyStore.getInstance(KeyStore.getDefaultType());
                cacerts.load(cacertsIs, cacertsPasswd.toCharArray());

            } catch (Exception e) {
                log.warn("CA certs could not be loaded: " + e.getMessage());
            } finally {
                if (cacertsIs != null) {
                    try {
                        cacertsIs.close();
                    } catch (IOException e) {
                        //ignore
                    }
                }
            }
        }
    }

    /**
     * A Hook for subclasses to set the keystore without having to
     * load it from an <code>InputStream</code>.
     *
     * @param ks existing keystore
     */
    public void setKeyStore(KeyStore ks) {
        keystore = ks;
    }

    public KeyStore getKeyStore() {
        return this.keystore;
    }

    /**
     * @return a crypto provider name.  This operation should
     *         return null if the default crypto provider should
     *         be used.
     */
    protected abstract String getCryptoProvider();


    private String mapKeystoreProviderToCertProvider(String s) {
        if ("SunJSSE".equals(s)) {
            return "SUN";
        }
        return s;
    }

    /**
     * Singleton certificate factory for this Crypto instance.
     * <p/>
     *
     * @return Returns a <code>CertificateFactory</code> to construct
     *         X509 certificates
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    public CertificateFactory getCertificateFactory() throws XMLSecurityException {
        String provider = getCryptoProvider();
        String keyStoreProvider = null;
        if (keystore != null) {
            keyStoreProvider = keystore.getProvider().getName();
        }

        //Try to find a CertificateFactory that generates certs that are fully
        //compatible with the certs in the KeyStore  (Sun -> Sun, BC -> BC, etc...)
        CertificateFactory factory = null;
        if (provider != null) {
            factory = certFactMap.get(provider);
        } else if (keyStoreProvider != null) {
            factory =
                    certFactMap.get(
                            mapKeystoreProviderToCertProvider(keyStoreProvider)
                    );
            if (factory == null) {
                factory = certFactMap.get(keyStoreProvider);
            }
        } else {
            factory = certFactMap.get("DEFAULT");
        }
        if (factory == null) {
            synchronized (this) {
                try {
                    if (provider == null || provider.length() == 0) {
                        if (keyStoreProvider != null && keyStoreProvider.length() != 0) {
                            try {
                                factory =
                                        CertificateFactory.getInstance(
                                                "X.509",
                                                mapKeystoreProviderToCertProvider(keyStoreProvider)
                                        );
                                certFactMap.put(keyStoreProvider, factory);
                                certFactMap.put(
                                        mapKeystoreProviderToCertProvider(keyStoreProvider), factory
                                );
                            } catch (Exception ex) {
                                log.debug(ex);
                                //Ignore, we'll just use the default since they didn't specify one.
                                //Hopefully that will work for them.
                            }
                        }
                        if (factory == null) {
                            factory = CertificateFactory.getInstance("X.509");
                            certFactMap.put("DEFAULT", factory);
                        }
                    } else {
                        factory = CertificateFactory.getInstance("X.509", provider);
                        certFactMap.put(provider, factory);
                    }
                    certFactMap.put(factory.getProvider().getName(), factory);
                } catch (CertificateException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "unsupportedCertType", e);
                } catch (NoSuchProviderException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noSecProvider", e);
                }
            }
        }
        return factory;
    }

    /**
     * load a X509Certificate from the input stream.
     * <p/>
     *
     * @param in The <code>InputStream</code> array containing the X509 data
     * @return Returns a X509 certificate
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    public X509Certificate loadCertificate(InputStream in) throws XMLSecurityException {
        try {
            return (X509Certificate) getCertificateFactory().generateCertificate(in);
        } catch (CertificateException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "parseError", e);
        }
    }

    /**
     * Gets the private key identified by <code>alias</> and <code>password</code>.
     * <p/>
     *
     * @param alias    The alias (<code>KeyStore</code>) of the key owner
     * @param password The password needed to access the private key
     * @return The private key
     * @throws Exception
     */
    public PrivateKey getPrivateKey(String alias, String password) throws XMLSecurityException {
        if (alias == null) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "aliasIsNull");
        }
        try {
            boolean b = keystore.isKeyEntry(alias);
            if (!b) {
                String msg = "Cannot find key for alias: [" + alias + "]";
                String logMsg = createKeyStoreErrorMessage(keystore);
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "keyError", msg + logMsg);
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, null, e);
        }

        Key keyTmp;
        try {
            keyTmp = keystore.getKey(alias, password.toCharArray());
            if (!(keyTmp instanceof PrivateKey)) {
                String msg = "Key is not a private key, alias: [" + alias + "]";
                String logMsg = null;
                logMsg = createKeyStoreErrorMessage(keystore);
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "keyError", msg + logMsg);
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
        } catch (UnrecoverableKeyException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
        }
        return (PrivateKey) keyTmp;
    }

    protected static String createKeyStoreErrorMessage(KeyStore keystore) throws KeyStoreException {
        Enumeration<String> aliases = keystore.aliases();
        StringBuilder sb = new StringBuilder(keystore.size() * 7);
        boolean firstAlias = true;
        while (aliases.hasMoreElements()) {
            if (!firstAlias) {
                sb.append(", ");
            }
            sb.append(aliases.nextElement());
            firstAlias = false;
        }
        return " in keystore of type [" + keystore.getType()
                + "] from provider [" + keystore.getProvider()
                + "] with size [" + keystore.size() + "] and aliases: {"
                + sb.toString() + "}";
    }

    private Object createBCX509Name(String s) {
        if (BC_509CLASS_CONS != null) {
            try {
                return BC_509CLASS_CONS.newInstance(s);
            } catch (Exception e) {
                //ignore
            }
        }
        return new X500Principal(s);
    }

    public String getAliasForX509Cert(String issuer, BigInteger serialNumber) throws XMLSecurityException {
        Object issuerName;
        Certificate[] certificates;

        //
        // Convert the issuer DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        try {
            X500Principal issuerRDN = new X500Principal(issuer);
            issuerName = createBCX509Name(issuerRDN.getName());
        } catch (IllegalArgumentException ex) {
            issuerName = createBCX509Name(issuer);
        }

        try {
            for (Enumeration<String> e = keystore.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();
                Certificate[] certs = keystore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    Certificate cert = keystore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                    certificates = new Certificate[]{cert};
                } else {
                    certificates = certs;
                }
                if (!(certificates[0] instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509cert = (X509Certificate) certificates[0];
                if (x509cert.getSerialNumber().compareTo(serialNumber) == 0) {
                    Object certName = createBCX509Name(x509cert.getIssuerDN().getName());
                    if (certName.equals(issuerName)) {
                        return alias;
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "keystore", e);
        }
        return null;
    }

    /**
     * Lookup a X509 Certificate in the keystore according to a given serial number and
     * the issuer of a Certificate.
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate chain
     * for each alias. Then the SerialNumber and Issuer for each certificate of the chain
     * is compared with the parameters.
     *
     * @param issuer       The issuer's name for the certificate
     * @param serialNumber The serial number of the certificate from the named issuer
     * @return alias name of the certificate that matches serialNumber and issuer name
     *         or null if no such certificate was found.
     */
    public X509Certificate[] getCertificates(String issuer, BigInteger serialNumber) throws XMLSecurityException {
        Object issuerName;
        Certificate[] certificates;

        //
        // Convert the issuer DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        try {
            X500Principal issuerRDN = new X500Principal(issuer);
            issuerName = createBCX509Name(issuerRDN.getName());
        } catch (IllegalArgumentException ex) {
            issuerName = createBCX509Name(issuer);
        }

        try {
            for (Enumeration<String> e = keystore.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();
                Certificate[] certs = keystore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    Certificate cert = keystore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                    certificates = new Certificate[]{cert};
                } else {
                    certificates = certs;
                }
                if (!(certificates[0] instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509cert = (X509Certificate) certificates[0];
                if (x509cert.getSerialNumber().compareTo(serialNumber) == 0) {
                    Object certName = createBCX509Name(x509cert.getIssuerDN().getName());
                    if (certName.equals(issuerName)) {
                        X509Certificate[] x509certs = new X509Certificate[certificates.length];
                        for (int i = 0; i < certificates.length; i++) {
                            x509certs[i] = (X509Certificate) certificates[i];
                        }
                        return x509certs;
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "keystore", e);
        }
        return null;
    }

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
     * @throws org.swssf.ext.XMLSecurityException
     *          if problems during keystore handling or wrong certificate (no SKI data)
     */
    public String getAliasForX509Cert(byte[] skiBytes) throws XMLSecurityException {
        Certificate cert = null;

        try {
            for (Enumeration<String> e = keystore.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();
                Certificate[] certs = keystore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a  result.
                    cert = keystore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                } else {
                    cert = certs[0];
                }
                if (!(cert instanceof X509Certificate)) {
                    continue;
                }
                byte[] data = getSKIBytesFromCert((X509Certificate) cert);
                if (data.length != skiBytes.length) {
                    continue;
                }
                if (Arrays.equals(data, skiBytes)) {
                    return alias;
                }
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "keystore", e);
        }
        return null;
    }

    /**
     * Return a X509 Certificate alias in the keystore according to a given Certificate
     * <p/>
     *
     * @param cert The certificate to lookup
     * @return alias name of the certificate that matches the given certificate
     *         or null if no such certificate was found.
     */
    public String getAliasForX509Cert(Certificate cert) throws XMLSecurityException {
        try {
            if (keystore == null) {
                return null;
            }
            //
            // The following code produces the wrong alias in BouncyCastle and so
            // we'll just use the brute-force search
            //
            // String alias = keystore.getCertificateAlias(cert);
            // if (alias != null) {
            //     return alias;
            // }
            Enumeration<String> e = keystore.aliases();
            while (e.hasMoreElements()) {
                String alias = e.nextElement();
                X509Certificate cert2 = (X509Certificate) keystore.getCertificate(alias);
                if (cert2.equals(cert)) {
                    return alias;
                }
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "keystore", e);
        }
        return null;
    }


    /**
     * Gets the list of certificates for a given alias.
     * <p/>
     *
     * @param alias Lookup certificate chain for this alias
     * @return Array of X509 certificates for this alias name, or
     *         null if this alias does not exist in the keystore
     */
    public X509Certificate[] getCertificates(String alias) throws XMLSecurityException {
        Certificate[] certs = null;
        Certificate cert = null;
        try {
            if (this.keystore != null) {
                //There's a chance that there can only be a set of trust stores
                certs = keystore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a
                    // result.
                    cert = keystore.getCertificate(alias);
                }
            }

            if (certs == null && cert == null && cacerts != null) {
                // Now look into the trust stores
                certs = cacerts.getCertificateChain(alias);
                if (certs == null) {
                    cert = cacerts.getCertificate(alias);
                }
            }

            if (cert != null) {
                certs = new Certificate[]{cert};
            } else if (certs == null) {
                // At this point we don't have certs or a cert
                return null;
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "keystore", e);
        }

        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
    }

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
    public String getAliasForX509CertThumb(byte[] thumb) throws XMLSecurityException {
        Certificate cert = null;
        MessageDigest sha = null;

        try {
            sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noSHA1availabe", e);
        }
        try {
            for (Enumeration<String> e = keystore.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();
                Certificate[] certs = keystore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a  result.
                    cert = keystore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                } else {
                    cert = certs[0];
                }
                if (!(cert instanceof X509Certificate)) {
                    continue;
                }
                try {
                    sha.update(cert.getEncoded());
                } catch (CertificateEncodingException ex) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "encodeError", ex);
                }
                byte[] data = sha.digest();

                if (Arrays.equals(data, thumb)) {
                    return alias;
                }
            }
        } catch (KeyStoreException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "keystore", e);
        }
        return null;
    }

    /**
     * Reads the SubjectKeyIdentifier information from the certificate.
     * <p/>
     * If the the certificate does not contain a SKI extension then
     * try to compute the SKI according to RFC3280 using the
     * SHA-1 hash value of the public key. The second method described
     * in RFC3280 is not support. Also only RSA public keys are supported.
     * If we cannot compute the SKI throw a XMLSecurityException.
     *
     * @param cert The certificate to read SKI
     * @return The byte array containing the binary SKI data
     */
    public byte[] getSKIBytesFromCert(X509Certificate cert) throws XMLSecurityException {
        //
        // Gets the DER-encoded OCTET string for the extension value (extnValue)
        // identified by the passed-in oid String. The oid string is represented
        // by a set of positive whole numbers separated by periods.
        //
        byte[] derEncodedValue = cert.getExtensionValue(SKI_OID);

        if (cert.getVersion() < 3 || derEncodedValue == null) {
            PublicKey key = cert.getPublicKey();
            if (!(key instanceof RSAPublicKey)) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "noSKIHandling", "Support for RSA key only");
            }
            byte[] encoded = key.getEncoded();
            // remove 22-byte algorithm ID and header
            byte[] value = new byte[encoded.length - 22];
            System.arraycopy(encoded, 22, value, 0, value.length);
            MessageDigest sha;
            try {
                sha = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException ex) {
                throw new XMLSecurityException(
                        XMLSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "noSKIHandling",
                        ex, "Wrong certificate version (<3) and no SHA1 message digest availabe"
                );
            }
            sha.reset();
            sha.update(value);
            return sha.digest();
        }

        //
        // Strip away first four bytes from the DerValue (tag and length of
        // ExtensionValue OCTET STRING and KeyIdentifier OCTET STRING)
        //
        byte abyte0[] = new byte[derEncodedValue.length - 4];

        System.arraycopy(derEncodedValue, 4, abyte0, 0, abyte0.length);
        return abyte0;
    }

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
    public X509Certificate[] getX509Certificates(byte[] data, boolean reverse) throws XMLSecurityException {
        InputStream in = new ByteArrayInputStream(data);
        CertPath path = null;
        try {
            path = getCertificateFactory().generateCertPath(in);
        } catch (CertificateException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "parseError", e);
        }
        List<? extends Certificate> l = path.getCertificates();
        X509Certificate[] certs = new X509Certificate[l.size()];
        Iterator<? extends Certificate> iterator = l.iterator();
        for (int i = 0; i < l.size(); i++) {
            certs[(reverse) ? (l.size() - 1 - i) : i] = (X509Certificate) iterator.next();
        }
        return certs;
    }

    /**
     * Evaluate whether a given certificate chain should be trusted.
     * Uses the CertPath API to validate a given certificate chain.
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws org.swssf.ext.XMLSecurityException
     *
     */
    public boolean verifyTrust(X509Certificate[] certs) throws XMLSecurityException {
        try {
            // Generate cert path
            List<X509Certificate> certList = Arrays.asList(certs);
            CertPath path = getCertificateFactory().generateCertPath(certList);

            Set<TrustAnchor> set = new HashSet<TrustAnchor>();
            if (cacerts != null) {
                Enumeration<String> truststoreAliases = cacerts.aliases();
                while (truststoreAliases.hasMoreElements()) {
                    String alias = truststoreAliases.nextElement();
                    X509Certificate cert =
                            (X509Certificate) cacerts.getCertificate(alias);
                    if (cert != null) {
                        TrustAnchor anchor =
                                new TrustAnchor(cert, cert.getExtensionValue(NAME_CONSTRAINTS_OID));
                        set.add(anchor);
                    }
                }
            }

            // Add certificates from the keystore
            if (keystore != null) {
                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    X509Certificate cert =
                            (X509Certificate) keystore.getCertificate(alias);
                    if (cert != null) {
                        TrustAnchor anchor =
                                new TrustAnchor(cert, cert.getExtensionValue(NAME_CONSTRAINTS_OID));
                        set.add(anchor);
                    }
                }
            }

            PKIXParameters param = new PKIXParameters(set);

            // Do not check a revocation list
            param.setRevocationEnabled(false);

            // Verify the trust path using the above settings
            String provider = getCryptoProvider();
            CertPathValidator validator = null;
            if (provider == null || provider.length() == 0) {
                validator = CertPathValidator.getInstance("PKIX");
            } else {
                validator = CertPathValidator.getInstance("PKIX", provider);
            }
            validator.validate(path, param);
            return true;
        } catch (java.security.NoSuchProviderException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.FAILURE, "certpath",
                    e, e.getMessage()
            );
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.FAILURE,
                    "certpath", e, e.getMessage()
            );
        } catch (java.security.cert.CertificateException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.FAILURE, "certpath",
                    e, e.getMessage()
            );
        } catch (java.security.InvalidAlgorithmParameterException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.FAILURE, "certpath",
                    e, e.getMessage()
            );
        } catch (java.security.cert.CertPathValidatorException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.FAILURE, "certpath",
                    e, e.getMessage()
            );
        } catch (java.security.KeyStoreException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.FAILURE, "certpath",
                    e, e.getMessage()
            );
        }
    }

    /**
     * Evaluate whether a given public key should be trusted.
     *
     * @param publicKey The PublicKey to be evaluated
     * @return whether the PublicKey parameter is trusted or not
     */
    public boolean verifyTrust(PublicKey publicKey) throws XMLSecurityException {
        //
        // If the public key is null, do not trust the signature
        //
        if (publicKey == null) {
            return false;
        }

        //
        // Search the keystore for the transmitted public key (direct trust)
        //
        boolean trust = findPublicKeyInKeyStore(publicKey, keystore);
        if (trust) {
            return true;
        } else {
            //
            // Now search the truststore for the transmitted public key (direct trust)
            //
            trust = findPublicKeyInKeyStore(publicKey, cacerts);
            if (trust) {
                return true;
            }
        }
        return false;
    }

    /**
     * Find the Public Key in a keystore.
     */
    private boolean findPublicKeyInKeyStore(PublicKey publicKey, KeyStore keyStoreToSearch) {
        try {
            for (Enumeration<String> e = keyStoreToSearch.aliases(); e.hasMoreElements(); ) {
                String alias = e.nextElement();
                Certificate[] certs = keyStoreToSearch.getCertificateChain(alias);
                Certificate cert;
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a result.
                    cert = keyStoreToSearch.getCertificate(alias);
                    if (cert == null) {
                        continue;
                    }
                } else {
                    cert = certs[0];
                }
                if (!(cert instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509cert = (X509Certificate) cert;
                if (publicKey.equals(x509cert.getPublicKey())) {
                    return true;
                }
            }
        } catch (KeyStoreException e) {
            return false;
        }
        return false;
    }
}