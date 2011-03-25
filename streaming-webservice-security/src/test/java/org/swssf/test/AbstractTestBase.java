/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.test;

import org.swssf.WSSec;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEventListener;
import org.swssf.test.utils.StAX2DOM;
import org.swssf.test.utils.XmlReaderToWriter;
import com.ctc.wstx.api.WstxInputProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.handler.WSS4JHandler;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.rpc.JAXRPCException;
import javax.xml.rpc.handler.HandlerInfo;
import javax.xml.rpc.handler.MessageContext;
import javax.xml.rpc.handler.soap.SOAPMessageContext;
import javax.xml.soap.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public abstract class AbstractTestBase {

    //javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
    //transformer.transform(new StreamSource(new ByteArrayInputStream(baos.toByteArray())), new StreamResult(System.out));

    protected static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    protected DocumentBuilderFactory documentBuilderFactory;

    public AbstractTestBase() {
        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringComments(false);
        documentBuilderFactory.setCoalescing(false);
        documentBuilderFactory.setIgnoringElementContentWhitespace(false);
        xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(5 * 8192));
    }

    public Document doInboundSecurity(SecurityProperties securityProperties, InputStream inputStream) throws WSSecurityException, SecurityConfigurationException, XMLStreamException, ParserConfigurationException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), null);
    }

    public Document doInboundSecurity(SecurityProperties securityProperties, InputStream inputStream, SecurityEventListener securityEventListener) throws WSSecurityException, SecurityConfigurationException, XMLStreamException, ParserConfigurationException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), securityEventListener);
    }

    public Document doInboundSecurity(SecurityProperties securityProperties, XMLStreamReader xmlStreamReader) throws WSSecurityException, SecurityConfigurationException, XMLStreamException, ParserConfigurationException {
        return doInboundSecurity(securityProperties, xmlStreamReader, null);
    }

    public Document doInboundSecurity(SecurityProperties securityProperties, XMLStreamReader xmlStreamReader, SecurityEventListener securityEventListener) throws WSSecurityException, SecurityConfigurationException, XMLStreamException, ParserConfigurationException {
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader outXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader, securityEventListener);
        Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), outXmlStreamReader);
        return document;
    }

    protected ByteArrayOutputStream doOutboundSecurity(SecurityProperties securityProperties, InputStream sourceDocument) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        return baos;
    }

    protected Document doOutboundSecurityWithWSS4J(InputStream sourceDocument, String action, Properties properties) throws org.apache.ws.security.WSSecurityException {
        WSS4JHandler wss4JHandler = new WSS4JHandler();
        HandlerInfo handlerInfo = new HandlerInfo();
        wss4JHandler.init(handlerInfo);
        MessageContext messageContext = getMessageContext(sourceDocument);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTION, WSHandlerConstants.NO_SERIALIZATION + " " + action);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.USER, "transmitter");
        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.setProperty(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.setProperty("" + sigProperties.hashCode(), sigProperties);

        Properties encProperties = new Properties();
        encProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        encProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        encProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.setProperty(WSHandlerConstants.ENCRYPTION_USER, "receiver");
        messageContext.setProperty(WSHandlerConstants.ENC_PROP_REF_ID, "" + encProperties.hashCode());
        messageContext.setProperty("" + encProperties.hashCode(), encProperties);

        Enumeration enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.setProperty(s, properties.getProperty(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        wss4JHandler.doSender(messageContext, requestData, true);

        return (Document) messageContext.getProperty(WSHandlerConstants.SND_SECURITY);
    }

    protected Document doInboundSecurityWithWSS4J(Document document, String action) throws Exception {
        MessageContext messageContext = doInboundSecurityWithWSS4J_1(document, action);
        return ((Document) messageContext.getProperty(WSHandlerConstants.SND_SECURITY));
    }

    protected MessageContext doInboundSecurityWithWSS4J_1(Document document, String action) throws Exception {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        HandlerInfo handlerInfo = new HandlerInfo();
        wss4JHandler.init(handlerInfo);
        MessageContext messageContext = getMessageContext(document);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTION, action);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.USER, "receiver");
        //handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTOR, "receiver");
        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "receiver.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.setProperty(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.setProperty("" + sigProperties.hashCode(), sigProperties);
        messageContext.setProperty(WSHandlerConstants.PW_CALLBACK_REF, new WSS4JCallbackHandlerImpl());

        Properties decProperties = new Properties();
        decProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        decProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "receiver.jks");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        decProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.setProperty(WSHandlerConstants.DEC_PROP_REF_ID, "" + decProperties.hashCode());
        messageContext.setProperty("" + decProperties.hashCode(), decProperties);

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        wss4JHandler.doReceiver(messageContext, requestData, false);

        return messageContext;
    }

    private MessageContext getMessageContext(InputStream inputStream) {
        return getMessageContext(new StreamSource(inputStream));
    }

    private MessageContext getMessageContext(Document document) {
        return getMessageContext(new DOMSource(document));
    }

    private MessageContext getMessageContext(final Source inSource) {
        MessageContext messageContext = new SOAPMessageContext() {

            private Map properties = new HashMap();

            public void setProperty(String s, Object o) {
                properties.put(s, o);
            }

            public Object getProperty(String s) {
                return properties.get(s);
            }

            public void removeProperty(String s) {
                properties.remove(s);
            }

            public boolean containsProperty(String s) {
                return properties.containsKey(s);
            }

            public Iterator getPropertyNames() {
                return properties.keySet().iterator();
            }

            public SOAPMessage getMessage() {
                try {
                    MessageFactory messageFactory = MessageFactory.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL);
                    SOAPMessage soapMessage = messageFactory.createMessage();
                    soapMessage.getSOAPPart().setContent(inSource);
                    setProperty(WSHandlerConstants.SND_SECURITY, soapMessage.getSOAPHeader().getOwnerDocument());
                    return soapMessage;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            public void setMessage(SOAPMessage soapMessage) {
                throw new UnsupportedOperationException();
            }

            public String[] getRoles() {
                return new String[0];  //To change body of implemented methods use File | Settings | File Templates.
            }
        };
        return messageContext;
    }

    protected XPathExpression getXPath(String expression) throws XPathExpressionException {
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xPath = xPathFactory.newXPath();
        xPath.setNamespaceContext(
                new NamespaceContext() {
                    public String getNamespaceURI(String prefix) {
                        if (org.swssf.ext.Constants.PREFIX_DSIG.equals(prefix)) {
                            return org.swssf.ext.Constants.NS_DSIG;
                        } else if (org.swssf.ext.Constants.PREFIX_SOAPENV.equals(prefix)) {
                            return org.swssf.ext.Constants.NS_SOAP11;
                        } else if (org.swssf.ext.Constants.PREFIX_WSSE.equals(prefix)) {
                            return org.swssf.ext.Constants.NS_WSSE;
                        } else if (org.swssf.ext.Constants.PREFIX_WSU.equals(prefix)) {
                            return org.swssf.ext.Constants.NS_WSU;
                        } else if (org.swssf.ext.Constants.PREFIX_XENC.equals(prefix)) {
                            return org.swssf.ext.Constants.NS_XMLENC;
                        } else {
                            return null;
                        }
                    }

                    public String getPrefix(String namespaceURI) {
                        if (org.swssf.ext.Constants.NS_DSIG.equals(namespaceURI)) {
                            return org.swssf.ext.Constants.PREFIX_DSIG;
                        } else if (org.swssf.ext.Constants.NS_SOAP11.equals(namespaceURI)) {
                            return org.swssf.ext.Constants.PREFIX_SOAPENV;
                        } else if (org.swssf.ext.Constants.NS_WSSE.equals(namespaceURI)) {
                            return org.swssf.ext.Constants.PREFIX_WSSE;
                        } else if (org.swssf.ext.Constants.NS_WSU.equals(namespaceURI)) {
                            return org.swssf.ext.Constants.PREFIX_WSU;
                        } else if (org.swssf.ext.Constants.NS_XMLENC.equals(namespaceURI)) {
                            return org.swssf.ext.Constants.PREFIX_XENC;
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

    class CustomWSS4JHandler extends WSS4JHandler {

        private final Log log = LogFactory.getLog(CustomWSS4JHandler.class.getName());
        private final boolean doDebug = log.isDebugEnabled();

        @Override
        public boolean doReceiver(MessageContext mc, RequestData reqData, boolean isRequest) throws org.apache.ws.security.WSSecurityException {
            Vector actions = new Vector();
            String action = (String) getOption(WSHandlerConstants.RECEIVE + '.' + WSHandlerConstants.ACTION);
            if (action == null) {
                action = (String) getOption(WSHandlerConstants.ACTION);
                if (action == null) {
                    action = (String) mc.getProperty(WSHandlerConstants.ACTION);
                }
            }
            if (action == null) {
                throw new JAXRPCException("WSS4JHandler: No action defined");
            }
            int doAction = WSSecurityUtil.decodeAction(action, actions);

            String actor = (String) getOption(WSHandlerConstants.ACTOR);

            SOAPMessage message = ((SOAPMessageContext) mc).getMessage();
            //SOAPPart sPart = message.getSOAPPart();

            Document doc = null;
            try {
                doc = message.getSOAPHeader().getOwnerDocument();
            } catch (SOAPException e) {
                throw new JAXRPCException(e);
            }


            /* hmmmmmmmmm????
        Document doc = null;
        try {
            doc = messageToDocument(message);
        } catch (Exception ex) {
            if (doDebug) {
                log.debug(ex.getMessage(), ex);
            }
            throw new JAXRPCException("WSS4JHandler: cannot convert into document",
                    ex);
        }
        */
            /*
            * Check if it's a fault. Don't process faults.
            *
            */
            org.apache.ws.security.SOAPConstants soapConstants =
                    WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
            if (WSSecurityUtil
                    .findElement(doc.getDocumentElement(),
                            "Fault",
                            soapConstants.getEnvelopeURI())
                    != null) {
                return false;
            }

            /*
            * To check a UsernameToken or to decrypt an encrypted message we need
            * a password.
            */
            CallbackHandler cbHandler = null;
            if ((doAction & (WSConstants.ENCR | WSConstants.UT)) != 0) {
                cbHandler = getPasswordCB(reqData);
            }

            /*
            * Get and check the Signature specific parameters first because they
            * may be used for encryption too.
            */
            doReceiverAction(doAction, reqData);

            Vector wsResult = null;
            try {
                wsResult =
                        secEngine.processSecurityHeader(doc,
                                actor,
                                cbHandler,
                                reqData.getSigCrypto(),
                                reqData.getDecCrypto());
            } catch (org.apache.ws.security.WSSecurityException ex) {
                if (doDebug) {
                    log.debug(ex.getMessage(), ex);
                }
                throw new JAXRPCException("WSS4JHandler: security processing failed",
                        ex);
            }
            if (wsResult == null) {         // no security header found
                if (doAction == WSConstants.NO_SECURITY) {
                    return true;
                } else {
                    throw new JAXRPCException("WSS4JHandler: Request does not contain required Security header");
                }
            }
            if (reqData.getWssConfig().isEnableSignatureConfirmation() && !isRequest) {
                checkSignatureConfirmation(reqData, wsResult);
            }

            /*
            * If we had some security processing, get the original
            * SOAP part of Axis' message and replace it with new SOAP
            * part. This new part may contain decrypted elements.
            */

            /* hmmmmmmmmmmmm ?????
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, os, true);
        try {
            sPart.setContent(new StreamSource(new ByteArrayInputStream(os.toByteArray())));
        } catch (SOAPException se) {
            if (doDebug) {
                log.debug(se.getMessage(), se);
            }
            throw new JAXRPCException(
                "Couldn't set content on SOAPPart" + se.getMessage(), se
            );
        }

        */

            if (doDebug) {
                log.debug("Processed received SOAP request");
            }

            /*
            * After setting the new current message, probably modified because
            * of decryption, we need to locate the security header. That is,
            * we force Axis (with getSOAPEnvelope()) to parse the string, build
            * the new header. Then we examine, look up the security header
            * and set the header as processed.
            *
            * Please note: find all header elements that contain the same
            * actor that was given to processSecurityHeader(). Then
            * check if there is a security header with this actor.
            */

            SOAPHeader sHeader = null;
            try {
                sHeader = message.getSOAPPart().getEnvelope().getHeader();
            } catch (Exception ex) {
                if (doDebug) {
                    log.debug(ex.getMessage(), ex);
                }
                throw new JAXRPCException("WSS4JHandler: cannot get SOAP header after security processing", ex);
            }
/*
        Iterator headers = sHeader.examineHeaderElements(actor);

        SOAPHeaderElement headerElement = null;
        while (headers.hasNext()) {
            SOAPHeaderElement hE = (SOAPHeaderElement) headers.next();
            if (hE.getElementName().getLocalName().equals(WSConstants.WSSE_LN)
                    && ((org.w3c.dom.Node) hE).getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                headerElement = hE;
                break;
            }
        }
  */
            /* JAXRPC conversion changes */
//        headerElement.setMustUnderstand(false); // is this sufficient?

            /*
            * Now we can check the certificate used to sign the message.
            * In the following implementation the certificate is only trusted
            * if either it itself or the certificate of the issuer is installed
            * in the keystore.
            *
            * Note: the method verifyTrust(X509Certificate) allows custom
            * implementations with other validation algorithms for subclasses.
            */

            // Extract the signature action result from the action vector

            WSSecurityEngineResult actionResult = WSSecurityUtil.fetchActionResult(wsResult, WSConstants.SIGN);

            if (actionResult != null) {
                X509Certificate returnCert =
                        (X509Certificate) actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);

                if (returnCert != null && !verifyTrust(returnCert, reqData)) {
                    throw new JAXRPCException("WSS4JHandler: The certificate used for the signature is not trusted");
                }
            }

            /*
            * Perform further checks on the timestamp that was transmitted in the header.
            * In the following implementation the timestamp is valid if it was
            * created after (now-ttl), where ttl is set on server side, not by the client.
            *
            * Note: the method verifyTimestamp(Timestamp) allows custom
            * implementations with other validation algorithms for subclasses.
            */

            // Extract the timestamp action result from the action vector
            actionResult = WSSecurityUtil.fetchActionResult(wsResult, WSConstants.TS);

            if (actionResult != null) {
                Timestamp timestamp =
                        (Timestamp) actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);

                if (timestamp != null && reqData.getWssConfig().isTimeStampStrict()
                        && !verifyTimestamp(timestamp, decodeTimeToLive(reqData))) {
                    throw new JAXRPCException("WSS4JHandler: The timestamp could not be validated");
                }
            }

            /*
            * now check the security actions: do they match, in right order?
            */
            if (!checkReceiverResults(wsResult, actions)) {
                throw new JAXRPCException("WSS4JHandler: security processing failed (actions mismatch)");
            }

            /*
            * All ok up to this point. Now construct and setup the
            * security result structure. The service may fetch this
            * and check it.
            */
            Vector results = null;
            if ((results = (Vector) mc.getProperty(WSHandlerConstants.RECV_RESULTS))
                    == null) {
                results = new Vector();
                mc.setProperty(WSHandlerConstants.RECV_RESULTS, results);
            }
            WSHandlerResult rResult =
                    new WSHandlerResult(actor,
                            wsResult);
            results.add(0, rResult);
            if (doDebug) {
                log.debug("WSS4JHandler: exit invoke()");
            }

            return true;
        }
    }
}
