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
import sun.security.util.DerValue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
    private static CertificateFactory certFact;
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
        disc.addClassLoader( JDKHooks.getJDKHooks().getThreadContextClassLoader() );
        disc.addClassLoader( this.getClass().getClassLoader() );
        ResourceIterator iterator = disc.findResources(location);
        if(iterator.hasNext()) {
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
     * @return	Returns a <code>CertificateFactory</code> to construct
     * 			X509 certficates
     * @throws	WSSecurityException
     */
    public synchronized CertificateFactory getCertificateFactory() throws WSSecurityException {
        if (certFact == null) {
			try {
	            String provider = properties.getProperty("org.apache.ws.security.crypto.merlin.cert.provider");
	            if(provider == null || provider.length() == 0) {
	            	certFact = CertificateFactory.getInstance("X.509");
	            }
	            else {
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
     * @param in	The <code>InputStream</code> array containg the X509 data
     * @return		Returns a X509 certificate
     * @throws 		WSSecurityException 
     */
    public X509Certificate loadCertificate(InputStream in) throws WSSecurityException {
		X509Certificate cert = null;
		try {
			cert =
				(X509Certificate) getCertificateFactory().generateCertificate(
					in);
		} catch (CertificateException e) {
			throw new WSSecurityException(
				WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
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
     * @return		An array of X509 certificates, ordered according to
     * 				the reverse flag
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
     * @throws WSSecurityException                  
     * @return		The byte array for the certficates ordered according
     * to the reverse flag
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
     * @throws Exception 
     * @return		The private key
     */
    public PrivateKey getPrivateKey(String alias, String password) throws Exception {
        if(alias == null) {
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
		return vr;
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


    /*
     * need to check if "getCertificateChain" also finds certificates that are
     * used for enryption only, i.e. they may not be signed by a CA
     * Otherwise we must define a restriction how to use certificate:
     * each certificate must be signed by a CA or is a self signed Certificate
     * (this should work as well).
     * --- remains to be tested in several ways --
     */
    public String getAliasForX509Cert(String issuer, BigInteger serialNumber)
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
				if (x509cert.getSerialNumber().compareTo(serialNumber) == 0) {
					certRDN = splitAndTrim(x509cert.getIssuerDN().getName());
					if (certRDN.equals(issuerRDN)) {
						return alias;
					}
				}
			}
		} catch (KeyStoreException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
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
	 * @param skiBytes       The SKI info bytes
	 * @return alias name of the certificate that matches serialNumber and issuer name
	 *         or null if no such certificate was found.
     * @exception WSSecurityException if problems during keystore handling or wrong certificate (no SKI data)
	 */

	public String getAliasForX509Cert(byte[] skiBytes) throws WSSecurityException {
		String certIssuer[] = null;
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
			throw new WSSecurityException(
				WSSecurityException.FAILURE,
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
			if(alias != null)
			    return alias;
			// Use brute force search
			Enumeration e = keystore.aliases();
			while(e.hasMoreElements()) {
			    alias = (String)e.nextElement();
			    X509Certificate cert2 = (X509Certificate) keystore.getCertificate(alias);
			    if(cert2.equals(cert)) {
			        return alias;
			    }
			}        
		} catch (KeyStoreException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "keystore");
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
    public X509Certificate[] getCertificates(String alias) throws WSSecurityException {
		Certificate[] certs = null;;
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
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
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
     * @param ks existing keystore
     */
    public void setKeyStore(KeyStore ks)
    {
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
            if(provider == null || provider.length() == 0) {
                keystore = KeyStore.getInstance
                        (properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type",
                                KeyStore.getDefaultType()));
            } else {
                keystore = KeyStore.getInstance
                        (properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.type",
                                KeyStore.getDefaultType()),provider);
            }
            String password = 
            	properties.getProperty("org.apache.ws.security.crypto.merlin.keystore.password",
                    				   "security");
            keystore.load(input, (password == null || password.length()==0) ? new char[0] : password.toCharArray());
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
	 * @param cert       The certificate to read SKI
	 * @return 			 The byte array conating the binary SKI data
	 */
	public byte[] getSKIBytesFromCert(X509Certificate cert)
		throws WSSecurityException {

		byte data[] = null;
		byte abyte0[] = null;
		if (cert.getVersion() < 3) {
			Object exArgs[] = { new Integer(cert.getVersion())};
			throw new WSSecurityException(
				1,
				"noSKIHandling",
				new Object[] { "Wrong certificate version (<3)" });
		}

		/*
		 * Gets the DER-encoded OCTET string for the extension value (extnValue)
		 * identified by the passed-in oid String. The oid string is
		 * represented by a set of positive whole numbers separated by periods.
		 */
		data = cert.getExtensionValue(SKI_OID);

		if (data == null) {
			throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				"noSKIHandling",
				new Object[] { "No extension data" });
		}
		DerValue derValue = null;
		try {
			derValue = new DerValue(data);
		} catch (IOException e) {
			throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				"noSKIHandling",
				new Object[] { "cannot read SKI value" });
		}

		if (derValue == null) {
			throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				"noSKIHandling",
				new Object[] { "No DER value" });
		}
		if (derValue.tag != DerValue.tag_OctetString) {
			throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				"noSKIHandling",
				new Object[] { "No octet string" });
		}
		byte[] extensionValue = null;
		try {
			extensionValue = derValue.getOctetString();
		} catch (IOException e1) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                "noSKIHandling",
                new Object[] { "cannot read SKI value as octet data" });
		}

		/**
		 * Strip away first two bytes from the DerValue (tag and length)
		 */
		abyte0 = new byte[extensionValue.length - 2];

		System.arraycopy(extensionValue, 2, abyte0, 0, abyte0.length);

		/*
		byte abyte0[] = new byte[derEncodedValue.length - 4];
		System.arraycopy(derEncodedValue, 4, abyte0, 0, abyte0.length);
		*/
		return abyte0;
	}

    public KeyStore getKeyStore()
    {
        return this.keystore;
    }
}

