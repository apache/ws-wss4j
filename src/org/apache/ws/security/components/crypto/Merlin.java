/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.components.crypto;

import org.apache.commons.discovery.Resource;
import org.apache.commons.discovery.ResourceIterator;
import org.apache.commons.discovery.jdk.JDKHooks;
import org.apache.commons.discovery.resource.DiscoverResources;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

/**
 * JDK1.4 based implementation of Crypto (uses keystore).
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class Merlin implements Crypto {
    private static Log log = LogFactory.getLog(Merlin.class);
    protected static CertificateFactory certFact;
    protected Properties properties = null;
    protected KeyStore keystore = null;

    /**
     * Constructor.
     * <p/>
     *
     * @param properties
     * @throws CredentialException
     * @throws IOException
     */
    public Merlin(Properties properties) throws CredentialException, IOException {
        /*
         * if no properties .. just return an instance, the rest will be
         * done later or this instance is just used to handle certificate
         * conversions in this implementatio
         */
        if (properties == null) {
            return;
        }
        this.properties = properties;
        String location = this.properties.getProperty("org.apache.ws.security.crypto.merlin.file");
        InputStream is = null;

        /**
         * Look for the keystore in classpaths
         */ 
        DiscoverResources disc = new DiscoverResources();
        disc.addClassLoader(JDKHooks.getJDKHooks().getThreadContextClassLoader());
        disc.addClassLoader(this.getClass().getClassLoader());
        ResourceIterator iterator = disc.findResources(location);
        if (iterator.hasNext()) {
            Resource resource = iterator.nextResource();
            is = resource.getResourceAsStream();
        } 
        
        /**
         * If we don't find it, then look on the file system.
         */ 
        if (is == null) {
            try {
                is = new FileInputStream(location);
            } catch (Exception e) {
                throw new CredentialException(3, "proxyNotFound", new Object[]{location});
            }
        }
         
        /**
         * Load the keystore
         */ 
        try {
            load(is);
        } finally {
            is.close();
        }
    }

    /**
     * Singleton certificate factory for this Crypto instance.
     * <p/>
     *
     * @return Returns a <code>CertificateFactory</code> to construct
     *         X509 certficates
     * @throws WSSecurityException
     */
    public synchronized CertificateFactory getCertificateFactory() throws WSSecurityException {
        if (certFact == null) {
            try {
                String provider = properties.getProperty("org.apache.ws.security.crypto.merlin.cert.provider");
                if (provider == null || provider.length() == 0) {
                    certFact = CertificateFactory.getInstance("X.509");
                } else {
                    certFact = CertificateFactory.getInstance("X.509", provider);
                }
            } catch (CertificateException e) {
                throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                        "unsupportedCertType");
            } catch (NoSuchProviderException e) {
                throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                        "noSecProvider");
            }
        }
        return certFact;
    }

    /**
     * load a X509Certificate from the input stream.
     * <p/>
     *
     * @param in The <code>InputStream</code> array containg the X509 data
     * @return Returns a X509 certificate
     * @throws WSSecurityException
     */
    public X509Certificate loadCertificate(InputStream in) throws WSSecurityException {
        X509Certificate cert = null;
        try {
            cert =
                    (X509Certificate) getCertificateFactory().generateCertificate(in);
        } catch (CertificateException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "parseError");
        }
        return cert;
    }

    /**
     * Construct an array of X509Certificate's from the byte array.
     * <p/>
     *
     * @param data    The <code>byte</code> array containg the X509 data
     * @param reverse If set the first certificate in input data will
     *                the last in the array
     * @return An array of X509 certificates, ordered according to
     *         the reverse flag
     * @throws WSSecurityException
     */
    public X509Certificate[] getX509Certificates(byte[] data, boolean reverse)
            throws WSSecurityException {
        InputStream in = new ByteArrayInputStream(data);
        CertPath path = null;
        try {
            path = getCertificateFactory().generateCertPath(in);
        } catch (CertificateException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "parseError");
        }
        List l = path.getCertificates();
        X509Certificate[] certs = new X509Certificate[l.size()];
        Iterator iterator = l.iterator();
        for (int i = 0; i < l.size(); i++) {
            certs[(reverse) ? (l.size() - 1 - i) : i] = (X509Certificate) iterator.next();
        }
        return certs;
    }

    /**
     * get a byte array given an array of X509 certificates.
     * <p/>
     *
     * @param reverse If set the first certificate in the array data will
     *                the last in the byte array
     * @param certs   The certificates to convert
     * @return The byte array for the certficates ordered according
     *         to the reverse flag
     * @throws WSSecurityException
     */
    public byte[] getCertificateData(boolean reverse, X509Certificate[] certs)
            throws WSSecurityException {
        Vector list = new Vector();
        for (int i = 0; i < certs.length; i++) {
            if (reverse) {
                list.insertElementAt(certs[i], 0);
            } else {
                list.add(certs[i]);
            }
        }
        try {
            CertPath path = getCertificateFactory().generateCertPath(list);
            return path.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "encodeError");
        } catch (CertificateException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "parseError");
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
    public PrivateKey getPrivateKey(String alias, String password) throws Exception {
        if (alias == null) {
            throw new Exception("alias is null");
        }
        boolean b = keystore.isKeyEntry(alias);
        if (!b) {
            log.error("Cannot find key for alias: " + alias);
            throw new Exception("Cannot find key for alias: " + alias);
        }
        Key keyTmp = keystore.getKey(alias, password.toCharArray());
        if (!(keyTmp instanceof PrivateKey)) {
            throw new Exception("Key is not a private key, alias: " + alias);
        }
        return (PrivateKey) keyTmp;
    }

    private Vector splitAndTrim(String inString) {
        X509NameTokenizer nmTokens = new X509NameTokenizer(inString);
        Vector vr = new Vector();

        while (nmTokens.hasMoreTokens()) {
            vr.add(nmTokens.nextToken());
        }
        java.util.Collections.sort(vr);
        return vr;
    }

    /**
     * Lookup a X509 Certificate in the keystore according to a given
     * the issuer of a Certficate.
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate chain
     * for each alias. Then the Issuer fo each certificate of the chain
     * is compared with the parameters.
     *
     * @param issuer The issuer's name for the certificate
     * @return alias name of the certificate that matches the issuer name
     *         or null if no such certificate was found.
     */
    public String getAliasForX509Cert(String issuer)
            throws WSSecurityException {
        return getAliasForX509Cert(issuer, null, false);
    }

    /**
     * Lookup a X509 Certificate in the keystore according to a given serial number and
     * the issuer of a Certficate.
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate chain
     * for each alias. Then the SerialNumber and Issuer fo each certificate of the chain
     * is compared with the parameters.
     *
     * @param issuer       The issuer's name for the certificate
     * @param serialNumber The serial number of the certificate from the named issuer
     * @return alias name of the certificate that matches serialNumber and issuer name
     *         or null if no such certificate was found.
     */
    public String getAliasForX509Cert(String issuer, BigInteger serialNumber)
            throws WSSecurityException {
        return getAliasForX509Cert(issuer, serialNumber, true);
    }

    /*
     * need to check if "getCertificateChain" also finds certificates that are
     * used for enryption only, i.e. they may not be signed by a CA
     * Otherwise we must define a restriction how to use certificate:
     * each certificate must be signed by a CA or is a self signed Certificate
     * (this should work as well).
     * --- remains to be tested in several ways --
     */
    private String getAliasForX509Cert(String issuer, BigInteger serialNumber,
                                       boolean useSerialNumber)
            throws WSSecurityException {
        Vector issuerRDN = splitAndTrim(issuer);
        X509Certificate x509cert = null;
        Vector certRDN = null;
        Certificate cert = null;

        try {
            for (Enumeration e = keystore.aliases(); e.hasMoreElements();) {
                String alias = (String) e.nextElement();
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
                x509cert = (X509Certificate) cert;
                if (!useSerialNumber ||
                        useSerialNumber && x509cert.getSerialNumber().compareTo(serialNumber) == 0) {
                    certRDN = splitAndTrim(x509cert.getIssuerDN().getName());
                    if (certRDN.equals(issuerRDN)) {
                        return alias;
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "keystore");
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
     * @throws WSSecurityException if problems during keystore handling or wrong certificate (no SKI data)
     */

    public String getAliasForX509Cert(byte[] skiBytes) throws WSSecurityException {
        Certificate cert = null;
        boolean found = false;

        try {
            for (Enumeration e = keystore.aliases(); e.hasMoreElements();) {
                String alias = (String) e.nextElement();
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
                for (int ii = 0; ii < data.length; ii++) {
                    if (data[ii] != skiBytes[ii]) {
                        found = false;
                        break;
                    }
                    found = true;
                }
                if (found) {
                    return alias;
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "keystore");
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

    /*
     * See comment above
     */
    public String getAliasForX509Cert(Certificate cert) throws WSSecurityException {
        try {
            String alias = keystore.getCertificateAlias(cert);
            if (alias != null)
                return alias;
            // Use brute force search
            Enumeration e = keystore.aliases();
            while (e.hasMoreElements()) {
                alias = (String) e.nextElement();
                X509Certificate cert2 = (X509Certificate) keystore.getCertificate(alias);
                if (cert2.equals(cert)) {
                    return alias;
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "keystore");
        }
        return null;
    }

    /**
     * Retrieves the alias name of the default certificate which has been
     * specified as a property. This should be the certificate that is used for
     * signature and encryption. This alias corresponds to the certificate that
     * should be used whenever KeyInfo is not poresent in a signed or
     * an encrypted message. May return null.
     *
     * @return alias name of the default X509 certificate
     */
    public String getDefaultX509Alias() {
        if (properties == null) {
            return null;
        }
        return properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.alias");
    }

    /**
     * Gets the list of certificates for a given alias.
     * <p/>
     *
     * @param alias Lookup certificate chain for this alias
     * @return Array of X509 certificates for this alias name, or
     *         null if this alias does not exist in the keystore
     */
    public X509Certificate[] getCertificates(String alias) throws WSSecurityException {
        Certificate[] certs = null;
        ;
        try {
            certs = keystore.getCertificateChain(alias);
            if (certs == null || certs.length == 0) {
                // no cert chain, so lets check if getCertificate gives us a  result.
                Certificate cert = keystore.getCertificate(alias);
                if (cert == null) {
                    return null;
                }
                certs = new Certificate[]{cert};
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "keystore");
        }
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509certs[i] = (X509Certificate) certs[i];
        }
        return x509certs;
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

    /**
     * Loads the the keystore from an <code>InputStream </code>.
     * <p/>
     *
     * @param input <code>InputStream</code> to read from
     * @throws CredentialException
     */
    public void load(InputStream input) throws CredentialException {
        if (input == null) {
            throw new IllegalArgumentException("input stream cannot be null");
        }
        try {
            String provider = properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.provider");
            if (provider == null || provider.length() == 0) {
                keystore = KeyStore.getInstance
                        (properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type",
                                KeyStore.getDefaultType()));
            } else {
                keystore = KeyStore.getInstance
                        (properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type",
                                KeyStore.getDefaultType()), provider);
            }
            String password =
                    properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.password",
                            "security");
            keystore.load(input, (password == null || password.length() == 0) ? new char[0] : password.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
            throw new CredentialException(3, "ioError00", e);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new CredentialException(3, "secError00", e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CredentialException(-1, "error00", e);
        }
    }

    static String SKI_OID = "2.5.29.14";

    /**
     * Reads the SubjectKeyIdentifier information from the certificate.
     * <p/>
     *
     * @param cert The certificate to read SKI
     * @return The byte array conating the binary SKI data
     */
    public byte[] getSKIBytesFromCert(X509Certificate cert)
            throws WSSecurityException {
        /*
         * Gets the DER-encoded OCTET string for the extension value (extnValue)
         * identified by the passed-in oid String. The oid string is
         * represented by a set of positive whole numbers separated by periods.
         */
        byte[] derEncodedValue = cert.getExtensionValue(SKI_OID);

        if (cert.getVersion() < 3) {
            throw new WSSecurityException(1,
                    "noSKIHandling",
                    new Object[]{"Wrong certificate version (<3)"});
        }

        /**
         * Strip away first four bytes from the DerValue (tag and length of
         * ExtensionValue OCTET STRING and KeyIdentifier OCTET STRING)
         */
        byte abyte0[] = new byte[derEncodedValue.length - 4];

        System.arraycopy(derEncodedValue, 4, abyte0, 0, abyte0.length);
        return abyte0;
    }

    public KeyStore getKeyStore() {
        return this.keystore;
    }

    /**
     * Uses the CertPath API to validate a given certificate chain
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    public boolean validateCertPath(X509Certificate[] certs) throws WSSecurityException {

        try {
            // Generate cert path
            java.util.List certList = java.util.Arrays.asList(certs);
            CertPath path = this.getCertificateFactory().generateCertPath(certList);

            // Use the certificates in the keystore as TrustAnchors
            PKIXParameters param = new PKIXParameters(this.keystore);

            // Do not check a revocation list
            param.setRevocationEnabled(false);

            // Verify the trust path using the above settings            
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            certPathValidator.validate(path, param);
        } catch (NoSuchAlgorithmException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "certpath",
                    new Object[]{ex.getMessage()},
                    (Throwable) ex);
        } catch (CertificateException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "certpath",
                    new Object[]{ex.getMessage()},
                    (Throwable) ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "certpath",
                    new Object[]{ex.getMessage()},
                    (Throwable) ex);
        } catch (CertPathValidatorException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "certpath",
                    new Object[]{ex.getMessage()},
                    (Throwable) ex);
        } catch (KeyStoreException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "certpath",
                    new Object[]{ex.getMessage()},
                    (Throwable) ex);
        }

        return true;
    }

    /**
     * Lookup X509 Certificates in the keystore according to a given DN of the subject of the certificate
     * <p/>
     * The search gets all alias names of the keystore and gets the certificate (chain)
     * for each alias. Then the DN of the certificate is compared with the parameters.
     *
     * @param subjectDN The DN of subject to look for in the keystore
     * @return Vector with all alias of certificates with the same DN as given in the parameters
     * @throws WSSecurityException
     */
    public String[] getAliasesForDN(String subjectDN) throws WSSecurityException {

        // Store the aliases found
        Vector aliases = new Vector();

        Certificate cert = null;
        
        // The DN to search the keystore for
        Vector subjectRDN = splitAndTrim(subjectDN);

        // Look at every certificate in the keystore
        try {
            for (Enumeration e = keystore.aliases(); e.hasMoreElements();) {
                String alias = (String) e.nextElement();

                Certificate[] certs = keystore.getCertificateChain(alias);
                if (certs == null || certs.length == 0) {
                    // no cert chain, so lets check if getCertificate gives us a  result.
                    cert = keystore.getCertificate(alias);
                    if (cert == null) {
                        return null;
                    }
                    certs = new Certificate[]{cert};
                } else {
                    cert = certs[0];
                }
                if (cert instanceof X509Certificate) {
                    Vector foundRDN = splitAndTrim(((X509Certificate) cert).getSubjectDN().getName());

                    if (subjectRDN.equals(foundRDN)) {
                        aliases.add(alias);
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "keystore");
        }
        
        // Convert the vector into an array
        String[] result = new String[aliases.size()];
        for (int i = 0; i < aliases.size(); i++) result[i] = (String) aliases.elementAt(i);

        return result;
    }
}


