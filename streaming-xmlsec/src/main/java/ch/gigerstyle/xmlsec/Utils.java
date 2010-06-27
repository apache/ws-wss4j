package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.crypto.Crypto;
import ch.gigerstyle.xmlsec.crypto.WSSecurityException;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 5:19:41 PM
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
public class Utils {

    private Utils() {
    }

    public static String dropReferenceMarker(String reference) {
        if (reference.startsWith("#")) {
            return reference.substring(1);
        }
        return reference;
    }

    public static String getXMLEventAsString(XMLEvent xmlEvent) {
        int eventType = xmlEvent.getEventType();

        switch (eventType) {
            case XMLEvent.START_ELEMENT:
                return "START_ELEMENT";
            case XMLEvent.END_ELEMENT:
                return "END_ELEMENT";
            case XMLEvent.PROCESSING_INSTRUCTION:
                return "PROCESSING_INSTRUCTION";
            case XMLEvent.CHARACTERS:
                return "CHARACTERS";
            case XMLEvent.COMMENT:
                return "COMMENT";
            case XMLEvent.START_DOCUMENT:
                return "START_DOCUMENT";
            case XMLEvent.END_DOCUMENT:
                return "END_DOCUMENT";
            case XMLEvent.ATTRIBUTE:
                return "ATTRIBUTE";
            case XMLEvent.DTD:
                return "DTD";
            case XMLEvent.NAMESPACE:
                return "NAMESPACE";
            default:
                throw new IllegalArgumentException("Illegal XMLEvent received: " + eventType);
        }
    }

    public static void doCallback(CallbackHandler callbackHandler, Callback callback) throws XMLSecurityException {
        try {
            Callback[] callbacks = new Callback[]{callback};
            callbackHandler.handle(callbacks);
        } catch (IOException e) {
            throw new XMLSecurityException(e);
        } catch (UnsupportedCallbackException e) {
            throw new XMLSecurityException(e);
        }
    }
}
