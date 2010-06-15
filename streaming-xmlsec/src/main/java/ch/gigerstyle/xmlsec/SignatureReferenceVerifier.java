package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import org.bouncycastle.util.encoders.Base64;
import org.w3._2000._09.xmldsig_.ReferenceType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 3:26:38 PM
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
public class SignatureReferenceVerifier {

    private ReferenceType referenceType;

    private List<Transformer> transformers = new ArrayList<Transformer>();
    private DigestOutputStream digestOutputStream;

    public SignatureReferenceVerifier(ReferenceType referenceType) throws XMLSecurityException {
        this.referenceType = referenceType;
        try {
            createMessageDigest();
            buildTransformerChain();
        } catch (Exception e){
            throw new XMLSecurityException(e.getMessage(), e);
        }
    }

    private void createMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
        String digestAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(referenceType.getDigestMethod().getAlgorithm());
        MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm, "BC");
        this.digestOutputStream = new DigestOutputStream(messageDigest);
    }

    private void buildTransformerChain() {
        transformers.add(new Canonicalizer20010315ExclOmitCommentsTransformer(null));
    }

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException {
        for (int i = 0; i < transformers.size(); i++) {
            Transformer transformer = transformers.get(i);
            transformer.transform(xmlEvent, this.digestOutputStream);
        }
    }

    public void doFinal() throws XMLSecurityException {
        byte[] calculatedDigest = this.digestOutputStream.getDigestValue();
        System.out.println("Calculated Digest: " + new String(Base64.encode(calculatedDigest)));
        byte[] storedDigest = Base64.decode(referenceType.getDigestValue());
        System.out.println("Stored Digest: " + new String(Base64.encode(storedDigest)));

        if (!MessageDigest.isEqual(storedDigest, calculatedDigest)){
            throw new XMLSecurityException("Digest verification failed");
        }
    }
}
