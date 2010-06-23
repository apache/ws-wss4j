package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import org.bouncycastle.util.encoders.Base64;
import org.w3._2000._09.xmldsig_.SignatureType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

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
//todo inner class?
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
        String signatureAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(signatureType.getSignedInfo().getSignatureMethod().getAlgorithm());
        Signature signature = Signature.getInstance(signatureAlgorithm, "BC");

        //todo handle the all the possible key types
        String keyId = signatureType.getKeyInfo().getSecurityTokenReferenceType().getReferenceType().getURI();
        SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(Utils.dropReferenceMarker(keyId));
        Certificate certificate = CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(securityTokenProvider.getSecurityToken()));
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
