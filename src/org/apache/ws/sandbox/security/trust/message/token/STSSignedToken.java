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
package org.apache.ws.security.trust.message.token;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;

/**
 * @author Malinda Kaushalye
 *         <p/>
 *         Specially for usage of STS.
 *         Token Issuer developers can use this class to get their token signed.
 *         The cannonicalization algorithm used here is <code>http://www.w3.org/2001/10/xml-exc-c14n#</code>.
 *         <p/>
 *         According to the public key algorithm the signature algorithm is recognized.
 *         There are two such algorithms that are supported here.
 *         They are
 *         1.    http://www.w3.org/2000/09/xmldsig#dsa-sha1
 *         2.    http://www.w3.org/2000/09/xmldsig#rsa-sha1
 *         <p/>
 *         If the public key algorithm is not supported then a <code>WSSecurityException</code> is thrown.
 *         Else it creates an <code>XMLSignature</code> and signs it using private key of the Security Token Service
 */

public class STSSignedToken {

    private Element element;

    /**
     * @param docTobeSigned the document to be signed
     * @param crypto
     * @param alias         alias of the x509 certificate
     * @param password      password of that particular certificate of the keystore
     * @throws WSSecurityException
     */
    public STSSignedToken(Document docTobeSigned, Crypto crypto, String alias, String password) throws WSSecurityException {

        X509Certificate[] certs = crypto.getCertificates(alias);

        String pubKeyAlgo = certs[0].getPublicKey().getAlgorithm();
        String sigAlgo = "";
        String canonAlgo = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

        if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
            sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
            sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
        } else {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data",
                    new Object[]{"for Signature - unkown public key Algo"});
        }

        XMLSignature sig = null;
        try {
            sig = new XMLSignature(docTobeSigned, null, sigAlgo, canonAlgo);
            sig.addKeyInfo(certs[0]);
            sig.sign(crypto.getPrivateKey(alias, password));
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "UserNAmeTokenIssuer:signature over token failed");

        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "UserNAmeTokenIssuer:signature over token failed. General exception-kau");
        }

        this.element = sig.getElement();
    }

    /**
     * @return the signature element
     */
    public Element getElement() {
        return element;
    }

}
