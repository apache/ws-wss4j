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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * PKIPath Security Token.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class PKIPathSecurity extends BinarySecurity {
    public static final String TYPE = WSConstants.WSSE_NS + "#X509PKIPathv1";

    /**
     * Constructor.
     * <p/>
     * 
     * @param elem 
     * @throws WSSecurityException 
     */
    public PKIPathSecurity(Element elem) throws WSSecurityException {
        super(elem);
        if (!getValueType().equals(TYPE)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "invalidValueType", new Object[]{TYPE, getValueType()});
        }
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param doc 
     */
    public PKIPathSecurity(Document doc) {
        super(doc);
        setValueType(TYPE);
    }

    /**
     * get the X509Certificate array.
     * <p/>
     * 
     * @param reverse 
     * @return 
     * @throws GeneralSecurityException 
     * @throws IOException              
     */
    public X509Certificate[] getX509Certificates(boolean reverse) throws GeneralSecurityException, IOException {
        byte[] data = getToken();
        if (data == null) {
            return null;
        }
        X509Certificate[] certs = null;
        certs = CryptoFactory.getInstance().getX509Certificates(data, reverse);
        return certs;
    }

    /**
     * set the X509Certificate array.
     * <p/>
     * 
     * @param certs   
     * @param reverse 
     * @throws CertificateEncodingException 
     * @throws IOException                  
     */
    public void setX509Certificates(X509Certificate[] certs, boolean reverse) throws CertificateEncodingException, IOException {
        if (certs == null) {
            throw new IllegalArgumentException("data == null");
        }
        byte[] data = CryptoFactory.getInstance().getCertificateData(reverse, certs);
        setToken(data);
    }
}
