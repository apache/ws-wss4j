package ch.gigerstyle.xmlsec;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.util.XMLEventAllocator;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 3:52:53 PM
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
public class Constants {
    public static final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
    public static final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();

    public static final XMLEventFactory xmlEventFactory = XMLEventFactory.newFactory();

    protected static final XMLEventAllocator xmlEventAllocator = new XMLEventNSAllocator();

    static {
        xmlInputFactory.setEventAllocator(xmlEventAllocator);
    }

    private Constants(){
    }

    public static final String NS_XMLENC = "http://www.w3.org/2001/04/xmlenc#";
    public static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
    public static final String NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String NS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";

    public static final QName TAG_soap11_Envelope = new QName(NS_SOAP11, "Envelope", "env");
    public static final QName TAG_soap11_Header = new QName(NS_SOAP11, "Header", "env");
    public static final QName TAG_soap11_Body = new QName(NS_SOAP11, "Body", "env");

    public static final QName TAG_wsse_Security = new QName(NS_WSSE, "Security", "wsse");

    public static final QName TAG_xmlenc_EncryptedKey = new QName(NS_XMLENC, "EncryptedKey", "xenc");
    public static final QName ATT_NULL_Id = new QName(null, "Id");

    public static final QName TAG_xmlenc_EncryptionMethod = new QName(NS_XMLENC, "EncryptionMethod", "xenc");
    public static final QName ATT_NULL_Algorithm = new QName(null, "Algorithm");

    public static final QName TAG_dsig_KeyInfo = new QName(NS_DSIG, "KeyInfo", "ds");

    public static final QName TAG_wsse_SecurityTokenReference = new QName(NS_WSSE, "SecurityTokenReference", "wsse");
    public static final QName TAG_wsse_Reference = new QName(NS_WSSE, "Reference", "wsse");

    public static final QName TAG_wsse_KeyIdentifier = new QName(NS_WSSE, "KeyIdentifier", "wsse");
    public static final QName ATT_NULL_EncodingType = new QName(null, "EncodingType");
    public static final QName ATT_NULL_ValueType = new QName(null, "ValueType");

    public static final QName TAG_xenc_CipherData = new QName(NS_XMLENC, "CipherData", "xenc");

    public static final QName TAG_xenc_CipherValue = new QName(NS_XMLENC, "CipherValue", "xenc");

    public static final QName TAG_xenc_ReferenceList = new QName(NS_XMLENC, "ReferenceList", "xenc");

    public static final QName TAG_xenc_DataReference = new QName(NS_XMLENC, "DataReference", "xenc");
    public static final QName ATT_NULL_URI = new QName(null, "URI");

    public static final QName TAG_wsse_BinarySecurityToken = new QName(NS_WSSE, "BinarySecurityToken", "wsse");
    public static final QName ATT_wsu_Id = new QName(NS_WSU, "Id", "wsu");

    public static final QName ATT_NULL_Type = new QName(null, "Type");

    public static final QName TAG_xenc_EncryptedData = new QName(NS_XMLENC, "EncryptedData", "xenc");
    public static final QName TAG_xenc_EncryptionMethod = new QName(NS_XMLENC, "EncryptionMethod", "xenc");

    public static final QName TAG_dsig_Signature = new QName(NS_DSIG, "Signature", "dsig");

    public static final QName TAG_dsig_SignedInfo = new QName(NS_DSIG, "SignedInfo", "dsig");

    public static final QName TAG_dsig_CanonicalizationMethod = new QName(NS_DSIG, "CanonicalizationMethod", "dsig");

    public static final QName TAG_dsig_SignatureMethod = new QName(NS_DSIG, "SignatureMethod", "dsig");

    public static final QName TAG_dsig_Reference = new QName(NS_DSIG, "Reference", "dsig");

    public static final QName TAG_dsig_Transforms = new QName(NS_DSIG, "Transforms", "dsig");

    public static final QName TAG_dsig_Transform = new QName(NS_DSIG, "Transform", "dsig");

    public static final QName TAG_dsig_DigestMethod = new QName(NS_DSIG, "DigestMethod", "dsig");

    public static final QName TAG_dsig_DigestValue = new QName(NS_DSIG, "DigestValue", "dsig");

    public static final QName TAG_dsig_SignatureValue = new QName(NS_DSIG, "SignatureValue", "dsig");

    public static final QName TAG_wsu_Timestamp = new QName(NS_WSU, "Timestamp", "wsu");
    public static final QName TAG_wsu_Created = new QName(NS_WSU, "Created", "wsu");
    public static final QName TAG_wsu_Expires = new QName(NS_WSU, "Expires", "wsu");

    public static final String SOAPMESSAGE_NS11 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";
    public static final String X509TOKEN_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";
    
    public static final String X509_V3_TYPE = X509TOKEN_NS + "#X509v3";
    public static final String SKI_URI = X509TOKEN_NS + "#X509SubjectKeyIdentifier";

    public static final String THUMB_URI = SOAPMESSAGE_NS11 + "#" + "ThumbprintSHA1";

    public static final String CACHED_EVENTS = "CACHED_EVENTS";

    public enum Action {
        TIMESTAMP,
        SIGNATURE,
        ENCRYPT,
    }
}
