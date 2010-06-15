package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import org.bouncycastle.util.encoders.Base64;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.w3._2000._09.xmldsig_.SignatureType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.List;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 11:27:17 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SignatureVerifier {

    private SignatureType signatureType;
    private SecurityContext securityContext;

    private SignerOutputStream signerOutputStream;
    private Canonicalizer20010315Transformer canonicalizer20010315Transformer = new Canonicalizer20010315ExclOmitCommentsTransformer(null);

    public SignatureVerifier(SignatureType signatureType, SecurityContext securityContext) throws XMLSecurityException {
        this.signatureType = signatureType;
        this.securityContext = securityContext;

        try {
            createSignatureAlgorithm();
        } catch (Exception e) {
            throw new XMLSecurityException(e.getMessage(), e);
        }
    }

    private void createSignatureAlgorithm() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException {
        //todo read values from xml
        /*((org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType)
        ((SecurityTokenReferenceType)currentSignatureType.getKeyInfo().getContent().get(0)).getAny().get(0)).getURI()*/
        List<BinarySecurityTokenType> bst = ((XMLSecurityContext)securityContext).getAsList(BinarySecurityTokenType.class);

        String signatureAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(signatureType.getSignedInfo().getSignatureMethod().getAlgorithm());
        Signature signature = Signature.getInstance(signatureAlgorithm, "BC");

        //String pubCert = "MIIDEzCCAfugAwIBAgIBAzANBgkqhkiG9w0BAQUFADAgMQswCQYDVQQGEwJDSDERMA8GA1UEAxMIU3dpc3NkZWMwHhcNMDYwNTAxMTYyMjEwWhcNMzEwNDI1MTYyMjEwWjA7MQswCQYDVQQGEwJDSDERMA8GA1UEChMIU3dpc3NkZWMxDTALBgNVBAMTBFRlc3QxCjAIBgNVBAUTATMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM0BXDQYClTt417yIYrf579xbJ3GgIEuvn3MERwWQqN96fQW6HnT5nLbQvhzkNCWvdEA+IVFYGjBiupuFOqqxTrqf/7AU97aJd8w6SfUItoeDfKvPytj8xVdVgmmZkOObrxxFqve9nDknOdW6e8f07tyiZn7ujb8Vj0n1+QEZx2tAgMBAAGjgcAwgb0wCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFNRzj4QAiYWM69mIWCqD3JC+QBI8MEgGA1UdIwRBMD+AFJb+i8DmIQ0IIqgnBF4mmb8GGK1poSSkIjAgMQswCQYDVQQGEwJDSDERMA8GA1UEAxMIU3dpc3NkZWOCAQAwGgYDVR0RBBMwEYEPcGtpQHN3aXNzZGVjLmNoMAkGA1UdEgQCMAAwDQYJKoZIhvcNAQEFBQADggEBAJr48OTCNvb14stpTcpRo6PB59Kf7+rBaK+s5YdMD9mCS8TdZoQFJbeq9IUgOhpArxG6nEfvcQEk4DmujCBoOi9cEaa6LZ+VEHUHtUtL7n0cbTXpipf63i4hSyqHHnF/sfUNUjU0rxtynFEgsUsPgkK+DlARExMU8DPa69sCS2pK0CJzICQGaojAJHQtEp1CwxbEKoUP9Yf+E8xMT7x1e5RFPKw6UxyBJagpXHMyX71tCqdOIkHhA62gmnciF0LqYDz8QMApQlMu2rNRDR7/bMRWsjNU3+liT404s9lmO4JyCsLOUCP5DYXjJUBhFkZPPVaBXTNziCRDIyTeSOB+3mE=";
        //String pubCert = "MIIDHjCCAgagAwIBAgIBBDANBgkqhkiG9w0BAQUFADAgMQswCQYDVQQGEwJDSDERMA8GA1UEAxMIU3dpc3NkZWMwHhcNMDYwNTAxMTYyMzQ4WhcNMzEwNDI1MTYyMzQ4WjBGMQswCQYDVQQGEwJDSDERMA8GA1UEChMIU3dpc3NkZWMxGDAWBgNVBAMTD1JlZkFwcCBSZWNlaXZlcjEKMAgGA1UEBRMBNDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxvsAN3AlxDGEV+DV44m4c02PpAfFtu3mO2a4XV6aZuFPiWRnjfxZOYUyDH9hyGPX3tzGdDmNOC2u1vpeoDHyH8bOniW3mju0jU/nKdFK5pMesYVotcuAq1/+MGHEj31Uorgaukia3yKlDurZyT9AQva/yHn36ftrypq94WquAU8CAwEAAaOBwDCBvTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUpHoiKNGY2YsLBKxwIV+jURt858MwSAYDVR0jBEEwP4AUlv6LwOYhDQgiqCcEXiaZvwYYrWmhJKQiMCAxCzAJBgNVBAYTAkNIMREwDwYDVQQDEwhTd2lzc2RlY4IBADAaBgNVHREEEzARgQ9wa2lAc3dpc3NkZWMuY2gwCQYDVR0SBAIwADANBgkqhkiG9w0BAQUFAAOCAQEAIS1KrrPDxzROqMkK6JfpUMLPE//X2uFobcpNT2CHLZ5MHgmFKeDsm4EeO9zFgm6Rg6W7lFUIHZ3M1l0TwF0bwycaVRrmlvwmRbRZjzx/NkbloLecICkqVSmzo+O0OnyKWMxnlnl/1nKvyqc6OtQuL7Py3eOlj+oX4uB7+rK1pPeQuO1L0ywyncdEkKucoBZxlOPaDFLlle3T6TrICxlQDw4FSwc5FiQGY5q8Betjs3wF6pSz3tS3GxMnbjXwziDL3sTSJgTAo368IZm2PEdnZXKIcopkmVhqeLoGXBUrtQoXRYC104sZvDLdHFWKb2rX4RpOM1/6t9VkvYSs10RhwA==";
        String pubCert = bst.get(0).getValue();
        Certificate certificate = CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(Base64.decode(pubCert.getBytes())));
        signature.initVerify(certificate.getPublicKey());
        signerOutputStream = new SignerOutputStream(signature);
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException {
        canonicalizer20010315Transformer.transform(xmlEvent, signerOutputStream);
    }

    public void doFinal() throws XMLSecurityException {
        try {
            if (!signerOutputStream.verify(Base64.decode(signatureType.getSignatureValue().getValue()))) {
                throw new XMLSecurityException("Signature verification failed");
            }
        } catch (SignatureException e) {
            throw new XMLSecurityException(e.getMessage(), e);
        }
    }
}
