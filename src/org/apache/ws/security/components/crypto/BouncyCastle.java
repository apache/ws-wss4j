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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;
import java.util.Vector;

/**
 * Bouncy Castle crypto provider (for use with JDK1.3).
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class BouncyCastle implements Crypto {
    private static Log log = LogFactory.getLog(BouncyCastle.class);
    private static CertificateFactory certFact = null;
    private PrivateKey key = null;
    private X509Certificate[] certs = null;
    private Properties properties = null;

    static {
        Security.addProvider(new BouncyCastleProvider());
        installSecureRandomProvider();
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param properties 
     * @throws CredentialException 
     */
    public BouncyCastle(Properties properties) throws CredentialException {
        this.properties = properties;
        try {
            InputStream in = new FileInputStream(getProxyFile(this.properties));
            load(in);
        } catch (Exception e) {
            throw new CredentialException(3, "proxyNotFound", new Object[]{getProxyFile(this.properties)});
        }
    }

    /**
     * get the singleton certificate factory.
     * <p/>
     * 
     * @return 
     * @throws GeneralSecurityException 
     */
    private static synchronized CertificateFactory getCertificateFactory() throws GeneralSecurityException {
        if (certFact == null) {
            certFact = CertificateFactory.getInstance("X.509");
        }
        return certFact;
    }

    /**
     * loads certificate from an input stream.
     * <p/>
     * 
     * @param in 
     * @return 
     * @throws GeneralSecurityException 
     */
    public X509Certificate loadCertificate(InputStream in) throws GeneralSecurityException {
        return (X509Certificate) getCertificateFactory().generateCertificate(in);
    }

    /**
     * installs the secure random provider.
     */
    private static void installSecureRandomProvider() {
        String providerName = "cryptix.jce.provider.CryptixRandom";
        try {
            log.debug("Loading SecureRandom provider: " + providerName);
            Class providerClass = Class.forName(providerName);
            Security.insertProviderAt((Provider) providerClass.newInstance(), 1);
        } catch (Exception e) {
            log.debug("Unable to install PRNG. Using default PRNG.", e);
        }
    }

    /**
     * convert bytes into corresponding DER object.
     * <p/>
     * 
     * @param data 
     * @return 
     * @throws IOException 
     */
    private static DERObject toDERObject(byte[] data) throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        DERInputStream derInputStream = new DERInputStream(inStream);
        return derInputStream.readObject();
    }

    /**
     * get an array of certificates from a byte array.
     * <p/>
     * 
     * @param data    
     * @param reverse 
     * @return 
     * @throws IOException              
     * @throws GeneralSecurityException 
     */
    public X509Certificate[] getX509Certificates(byte[] data, boolean reverse) throws IOException, GeneralSecurityException {
        X509Certificate[] certs;
        DERObject obj = BouncyCastle.toDERObject(data);
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        int size = seq.size();
        ByteArrayInputStream in;
        certs = new X509Certificate[size];
        for (int i = 0; i < size; i++) {
            obj = seq.getObjectAt(i).getDERObject();
            data = BouncyCastle.toByteArray(obj);
            in = new ByteArrayInputStream(data);
            certs[(reverse) ? (size - 1 - i) : i] = loadCertificate(in);
        }
        return certs;
    }

    /**
     * get a byte array given an array of certificates.
     * <p/>
     * 
     * @param reverse 
     * @param certs   
     * @return 
     * @throws IOException                  
     * @throws CertificateEncodingException 
     */
    public byte[] getCertificateData(boolean reverse, X509Certificate[] certs) throws IOException, CertificateEncodingException {
        DEREncodableVector vec = new DEREncodableVector();
        if (reverse) {
            for (int i = certs.length - 1; i >= 0; i--) {
                vec.add(BouncyCastle.toDERObject(certs[i].getEncoded()));
            }
        } else {
            for (int i = 0; i < certs.length; i++) {
                vec.add(BouncyCastle.toDERObject(certs[i].getEncoded()));
            }
        }
        DERSequence seq = new DERSequence(vec);
        byte[] data = BouncyCastle.toByteArray(seq);
        return data;
    }

    /**
     * load the private key and certificates from the input stream.
     * <p/>
     * 
     * @param input 
     * @throws Exception 
     */
    private void load(InputStream input) throws Exception {
        if (input == null) {
            throw new IllegalArgumentException("input stream cannot be null");
        }
        PrivateKey key = null;
        X509Certificate cert = null;
        Vector chain = new Vector(3);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(input));
            String s;
            while ((s = reader.readLine()) != null) {
                if (s.indexOf("BEGIN CERTIFICATE") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    cert = loadCertificate(new ByteArrayInputStream(data));
                    chain.addElement(cert);
                } else if (s.indexOf("BEGIN RSA PRIVATE KEY") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    key = getKey("RSA", data);
                }
            }
        } catch (IOException e) {
            throw new CredentialException(3, "ioError00", e);
        } catch (GeneralSecurityException e) {
            throw new CredentialException(3, "secError00", e);
        } catch (Exception e) {
            throw new CredentialException(-1, "error00", e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                }
            }
        }
        int size = chain.size();
        if (size == 0) {
            throw new CredentialException(3, "noCerts00", (Exception) null);
        }
        if (key == null) {
            throw new CredentialException(3, "noKey00", (Exception) null);
        } else {
            certs = new X509Certificate[size];
            chain.copyInto(certs);
            this.key = key;
            return;
        }
    }

    /**
     * convert a DER object into its byte representation.
     * <p/>
     * 
     * @param obj 
     * @return 
     * @throws IOException 
     */
    private static byte[] toByteArray(DERObject obj) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream der = new DEROutputStream(bout);
        der.writeObject(obj);
        return bout.toByteArray();
    }

    /**
     * get the decoded information.
     * <p/>
     * 
     * @param reader 
     * @return 
     * @throws IOException 
     */
    private static final byte[] getDecodedPEMObject(BufferedReader reader) throws Exception {
        StringBuffer buf = new StringBuffer();
        String s;
        while ((s = reader.readLine()) != null) {
            if (s.indexOf("--END") != -1) {
                try {
                    return Base64.decode(buf.toString());
                } catch (Base64DecodingException e) {
                    throw new Exception("Unable to decode Base64 encoded data", e);
                }
            }
            buf.append(s);
        }
        throw new Exception("PEM footer missing");
    }

    /**
     * get the private key from the byte array.
     * <p/>
     * 
     * @param alg  
     * @param data 
     * @return 
     * @throws GeneralSecurityException 
     */
    private PrivateKey getKey(String alg, byte[] data) throws GeneralSecurityException {
        if (alg.equals("RSA")) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(data);
                byte[] keyData = getKeyData(bis);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyData);
                KeyFactory kfac = KeyFactory.getInstance("RSA");
                return kfac.generatePrivate(spec);
            } catch (IOException e) {
                return null;
            }
        } else {
            return null;
        }
    }

    /**
     * construct the private key byte representation from the info in the input stream.
     * <p/>
     * 
     * @param bis 
     * @return 
     * @throws IOException 
     */
    private byte[] getKeyData(InputStream bis) throws IOException {
        DERInputStream derin = new DERInputStream(bis);
        DERObject keyInfo = derin.readObject();
        DERObjectIdentifier rsa_oid = PKCSObjectIdentifiers.rsaEncryption;
        AlgorithmIdentifier rsa = new AlgorithmIdentifier(rsa_oid);
        PrivateKeyInfo pkeyinfo = new PrivateKeyInfo(rsa, keyInfo);
        DERObject derkey = pkeyinfo.getDERObject();
        byte[] keyData = toByteArray(derkey);
        return keyData;
    }

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
    public X509Certificate[] getCertificates(String alias) throws Exception {
        throw new RuntimeException("Not Yet Implemented");
        /*
        certs = keystore.getCertificateChain(alias);
        if (certs == null) {
            return null;
        }
        return getCertificates();
        */
    }

    /**
     * get the list of certificates.
     * <p/>
     * 
     * @return 
     */
    public X509Certificate[] getCertificates() {
        return certs;
    }

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
     *         <p/>
     *         See comment above
     */
    /*
     * See comment above
     */
    public String getAliasForX509Cert(Certificate cert) throws Exception {
        throw new RuntimeException("Not Yet Implemented");
    }

    /**
     * Search a X509 Certificate in the keystore according to a given serial number and
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
    public String getAliasForX509Cert(String issuer, BigInteger serialNumber) throws Exception {
        throw new RuntimeException("Not Yet Implemented");
    }

    /**
     * get the private key.
     * <p/>
     * 
     * @return 
     */
    public PrivateKey getPrivateKey() {
        return key;
    }

    public PrivateKey getPrivateKey(String alias, String password) throws Exception {
        throw new RuntimeException("Not Yet Implemented");
    }

    /**
     * get the name of the file where the key/certificate information is stored.
     * <p/>
     * 
     * @param properties 
     * @return 
     */
    private static String getProxyFile(Properties properties) {
        String location = properties.getProperty("org.apache.ws.security.crypto.bouncycastle.file");
        if (location != null) {
            return location;
        } else {
            return getProxyDefaultLocation();
        }
    }

    /**
     * get the default location.
     * <p/>
     * 
     * @return 
     */
    private static String getProxyDefaultLocation() {
        String dir = System.getProperty("user.home");
        File f = new File(dir, "x509.txt");
        return f.getAbsolutePath();
    }
}
