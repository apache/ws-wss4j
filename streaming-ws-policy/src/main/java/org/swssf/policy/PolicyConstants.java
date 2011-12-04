package org.swssf.policy;

import javax.xml.namespace.QName;

/**
 * User: giger
 * Date: 11/27/11
 * Time: 2:35 PM
 * Copyright 2011 Marc Giger gigerstyle@gmx.ch
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
public class PolicyConstants {

    public static final String NS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope";

    public static final String PREFIX_SOAPENV = "env";
    public static final String TAG_soap_Body_LocalName = "Body";

    public static final QName TAG_soap11_Body = new QName(NS_SOAP11, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap12_Body = new QName(NS_SOAP12, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
}
