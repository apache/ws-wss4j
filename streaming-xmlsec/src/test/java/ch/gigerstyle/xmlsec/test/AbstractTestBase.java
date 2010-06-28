package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.Constants;
import ch.gigerstyle.xmlsec.WSPasswordCallback;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.util.Iterator;

/**
 * User: giger
 * Date: Jun 16, 2010
 * Time: 9:07:10 PM
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
public abstract class AbstractTestBase {

    protected static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    protected DocumentBuilderFactory documentBuilderFactory;

    public AbstractTestBase() {
        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringComments(false);
        documentBuilderFactory.setCoalescing(false);
        documentBuilderFactory.setIgnoringElementContentWhitespace(false);
    }

    class CallbackHandlerImpl implements CallbackHandler {
        public void handle(javax.security.auth.callback.Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];

            if (pc.getUsage() == WSPasswordCallback.DECRYPT || pc.getUsage() == WSPasswordCallback.SIGNATURE) {
                pc.setPassword("refApp9876");
            } else {
                throw new UnsupportedCallbackException(pc, "Unrecognized CallbackHandlerImpl");
            }
        }
    }

    protected XPathExpression getXPath(String expression) throws XPathExpressionException {
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xPath = xPathFactory.newXPath();
        xPath.setNamespaceContext(
                new NamespaceContext() {
                    public String getNamespaceURI(String prefix) {
                        if (Constants.PREFIX_DSIG.equals(prefix)) {
                            return Constants.NS_DSIG;
                        } else if (Constants.PREFIX_SOAPENV.equals(prefix)) {
                            return Constants.NS_SOAP11;
                        } else if (Constants.PREFIX_WSSE.equals(prefix)) {
                            return Constants.NS_WSSE;
                        } else if (Constants.PREFIX_WSU.equals(prefix)) {
                            return Constants.NS_WSU;
                        } else if (Constants.PREFIX_XENC.equals(prefix)) {
                            return Constants.NS_XMLENC;
                        } else {
                            return null;
                        }
                    }

                    public String getPrefix(String namespaceURI) {
                        if (Constants.NS_DSIG.equals(namespaceURI)) {
                            return Constants.PREFIX_DSIG;
                        } else if (Constants.NS_SOAP11.equals(namespaceURI)) {
                            return Constants.PREFIX_SOAPENV;
                        } else if (Constants.NS_WSSE.equals(namespaceURI)) {
                            return Constants.PREFIX_WSSE;
                        } else if (Constants.NS_WSU.equals(namespaceURI)) {
                            return Constants.PREFIX_WSU;
                        } else if (Constants.NS_XMLENC.equals(namespaceURI)) {
                            return Constants.PREFIX_XENC;
                        } else {
                            return null;
                        }
                    }

                    public Iterator getPrefixes(String namespaceURI) {
                        return null;
                    }
                }
        );
        return xPath.compile(expression);
    }
}
