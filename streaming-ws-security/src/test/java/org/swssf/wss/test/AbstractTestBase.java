/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.wss.test;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.action.SignatureAction;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.swssf.wss.WSSec;
import org.swssf.wss.ext.*;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SecurityEventListener;
import org.swssf.xmlsec.test.utils.StAX2DOM;
import org.swssf.xmlsec.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.rpc.Call;
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
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractTestBase {

    //javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
    //transformer.transform(new StreamSource(new ByteArrayInputStream(baos.toByteArray())), new StreamResult(System.out));

    protected static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    protected static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
    protected DocumentBuilderFactory documentBuilderFactory;

    protected static final String SECURED_DOCUMENT = "securedDocument";

    static {
        LogManager.getLogManager().addLogger(Logger.getLogger("org.jcp.xml.dsig.internal.dom"));
        LogManager.getLogManager().getLogger("org.jcp.xml.dsig.internal.dom").setLevel(Level.FINE);
    }

    public AbstractTestBase() {
        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringComments(false);
        documentBuilderFactory.setCoalescing(false);
        documentBuilderFactory.setIgnoringElementContentWhitespace(false);
        xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        //xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT, new Integer(5 * 8192));
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream) throws WSSecurityException, WSSConfigurationException, XMLStreamException, ParserConfigurationException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), null);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream, SecurityEventListener securityEventListener) throws WSSecurityException, WSSConfigurationException, XMLStreamException, ParserConfigurationException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader) throws WSSecurityException, WSSConfigurationException, XMLStreamException, ParserConfigurationException {
        return doInboundSecurity(securityProperties, xmlStreamReader, null);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader, SecurityEventListener securityEventListener) throws WSSecurityException, XMLStreamException, ParserConfigurationException {
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader outXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader, new ArrayList<SecurityEvent>(), securityEventListener);
        return StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), outXmlStreamReader);
    }

    protected ByteArrayOutputStream doOutboundSecurity(WSSSecurityProperties securityProperties, InputStream sourceDocument) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        return baos;
    }

    protected Document doOutboundSecurityWithWSS4J(InputStream sourceDocument, String action, Properties properties) throws org.apache.ws.security.WSSecurityException {
        return doOutboundSecurityWithWSS4J(sourceDocument, action, properties, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    protected Document doOutboundSecurityWithWSS4J(InputStream sourceDocument, String action, Properties properties, String soapProtocol) throws org.apache.ws.security.WSSecurityException {
        MessageContext messageContext = doOutboundSecurityWithWSS4J_1(sourceDocument, action, properties, soapProtocol);
        return (Document) messageContext.getProperty(SECURED_DOCUMENT);
    }

    @SuppressWarnings("unchecked")
    protected MessageContext doOutboundSecurityWithWSS4J_1(InputStream sourceDocument, String action, final Properties properties, String soapProtocol) throws org.apache.ws.security.WSSecurityException {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        HandlerInfo handlerInfo = new HandlerInfo();
        wss4JHandler.init(handlerInfo);
        final MessageContext messageContext = getMessageContext(sourceDocument, soapProtocol);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTION, action);
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
            messageContext.setProperty(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        requestData.setNoSerialization(true);
        requestData.setCallbackHandler(new WSS4JCallbackHandlerImpl());
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setAction(new Integer(WSConstants.SIGN), new SignatureAction() {
            @Override
            public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData) throws org.apache.ws.security.WSSecurityException {

                CallbackHandler callbackHandler = handler.getPasswordCallbackHandler(reqData);
                org.apache.ws.security.WSPasswordCallback passwordCallback = handler.getPasswordCB(reqData.getSignatureUser(), actionToDo, callbackHandler, reqData);

                WSSecSignature wsSign = new WSSecSignature();
                wsSign.setWsConfig(reqData.getWssConfig());

                if (reqData.getSigKeyId() != 0) {
                    wsSign.setKeyIdentifierType(reqData.getSigKeyId());
                }
                if (reqData.getSigAlgorithm() != null) {
                    wsSign.setSignatureAlgorithm(reqData.getSigAlgorithm());
                }
                if (reqData.getSigDigestAlgorithm() != null) {
                    wsSign.setDigestAlgo(reqData.getSigDigestAlgorithm());
                }
                if (properties.getProperty("CanonicalizationAlgo") != null) {
                    wsSign.setSigCanonicalization(properties.getProperty("CanonicalizationAlgo"));
                }

                wsSign.setUserInfo(reqData.getSignatureUser(), passwordCallback.getPassword());
                if (reqData.getSignatureParts().size() > 0) {
                    wsSign.setParts(reqData.getSignatureParts());
                }

                try {
                    wsSign.build(doc, reqData.getSigCrypto(), reqData.getSecHeader());
                    reqData.getSignatureValues().add(wsSign.getSignatureValue());
                } catch (org.apache.ws.security.WSSecurityException e) {
                    throw new org.apache.ws.security.WSSecurityException("Error during Signature: ", e);
                }
            }
        });
        requestData.setWssConfig(wssConfig);
        wss4JHandler.doSender(messageContext, requestData, true);

        return messageContext;
    }

    protected Document doInboundSecurityWithWSS4J(Document document, String action) throws Exception {
        MessageContext messageContext = doInboundSecurityWithWSS4J_1(document, action);
        return ((Document) messageContext.getProperty(SECURED_DOCUMENT));
    }

    protected MessageContext doInboundSecurityWithWSS4J_1(Document document, String action) throws Exception {
        return doInboundSecurityWithWSS4J_1(document, action, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    protected MessageContext doInboundSecurityWithWSS4J_1(Document document, String action, String soapProtocol) throws Exception {
        return doInboundSecurityWithWSS4J_1(document, action, SOAPConstants.SOAP_1_1_PROTOCOL, new Properties(), false);
    }

    @SuppressWarnings("unchecked")
    protected MessageContext doInboundSecurityWithWSS4J_1(Document document, String action, String soapProtocol, Properties properties, boolean client) throws Exception {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        HandlerInfo handlerInfo = new HandlerInfo();
        wss4JHandler.init(handlerInfo);
        MessageContext messageContext = getMessageContext(document, soapProtocol);
        handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTION, action);
        if (client) {
            handlerInfo.getHandlerConfig().put(WSHandlerConstants.USER, "transmitter");
        } else {
            handlerInfo.getHandlerConfig().put(WSHandlerConstants.USER, "receiver");
        }
        handlerInfo.getHandlerConfig().putAll(properties);
        //handlerInfo.getHandlerConfig().put(WSHandlerConstants.ACTOR, "receiver");
        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        if (client) {
            sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        } else {
            sigProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "receiver.jks");
        }
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.setProperty(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.setProperty("" + sigProperties.hashCode(), sigProperties);
        if (properties.get(WSHandlerConstants.PW_CALLBACK_REF) != null) {
            messageContext.setProperty(WSHandlerConstants.PW_CALLBACK_REF, properties.get(WSHandlerConstants.PW_CALLBACK_REF));
        } else {
            messageContext.setProperty(WSHandlerConstants.PW_CALLBACK_REF, new WSS4JCallbackHandlerImpl());
        }

        Properties decProperties = new Properties();
        decProperties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        if (client) {
            decProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "transmitter.jks");
        } else {
            decProperties.setProperty("org.apache.ws.security.crypto.merlin.file", "receiver.jks");
        }
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", "default");
        decProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.setProperty(WSHandlerConstants.DEC_PROP_REF_ID, "" + decProperties.hashCode());
        messageContext.setProperty("" + decProperties.hashCode(), decProperties);

        Enumeration enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.setProperty(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        wss4JHandler.doReceiver(messageContext, requestData, false);

        return messageContext;
    }

    private MessageContext getMessageContext(InputStream inputStream, String soapProtocol) {
        return getMessageContext(new StreamSource(inputStream), soapProtocol);
    }

    private MessageContext getMessageContext(Document document, String soapProtocol) {
        return getMessageContext(new DOMSource(document), soapProtocol);
    }

    @SuppressWarnings("unchecked")
    private MessageContext getMessageContext(final Source inSource, final String soapProtocol) {
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
                    //MessageFactory messageFactory = MessageFactory.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL);
                    MessageFactory messageFactory = MessageFactory.newInstance(soapProtocol);
                    SOAPMessage soapMessage = messageFactory.createMessage();
                    soapMessage.getSOAPPart().setContent(inSource);
                    setProperty(SECURED_DOCUMENT, soapMessage.getSOAPHeader().getOwnerDocument());
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
                        if (WSSConstants.PREFIX_DSIG.equals(prefix)) {
                            return WSSConstants.NS_DSIG;
                        } else if (WSSConstants.PREFIX_SOAPENV.equals(prefix)) {
                            return WSSConstants.NS_SOAP11;
                        } else if (WSSConstants.PREFIX_WSSE.equals(prefix)) {
                            return WSSConstants.NS_WSSE10;
                        } else if (WSSConstants.PREFIX_WSU.equals(prefix)) {
                            return WSSConstants.NS_WSU10;
                        } else if (WSSConstants.PREFIX_XENC.equals(prefix)) {
                            return WSSConstants.NS_XMLENC;
                        } else {
                            return null;
                        }
                    }

                    public String getPrefix(String namespaceURI) {
                        if (WSSConstants.NS_DSIG.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_DSIG;
                        } else if (WSSConstants.NS_SOAP11.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_SOAPENV;
                        } else if (WSSConstants.NS_WSSE10.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_WSSE;
                        } else if (WSSConstants.NS_WSU10.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_WSU;
                        } else if (WSSConstants.NS_XMLENC.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_XENC;
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

    @SuppressWarnings("unchecked")
    class CustomWSS4JHandler extends WSHandler {

        private final Log log = LogFactory.getLog(CustomWSS4JHandler.class.getName());
        private final boolean doDebug = log.isDebugEnabled();
        private HandlerInfo handlerInfo;

        /**
         * Initializes the instance of the handler.
         */
        public void init(HandlerInfo hi) {
            handlerInfo = hi;
        }

        /**
         * Handles incoming web service requests and outgoing responses
         */
        public boolean doSender(MessageContext mc, RequestData reqData, boolean isRequest) throws org.apache.ws.security.WSSecurityException {

            reqData.getSignatureParts().clear();
            reqData.getEncryptParts().clear();
            reqData.setNoSerialization(true);
            /*
            * Get the action first.
            */
            Vector actions = new Vector();
            String action = (String) getOption(WSHandlerConstants.ACTION);
            if (action == null) {
                action = (String) mc.getProperty(WSHandlerConstants.ACTION);
            }
            if (action == null) {
                throw new JAXRPCException("WSS4JHandler: No action defined");
            }
            int doAction = WSSecurityUtil.decodeAction(action, actions);
            if (doAction == WSConstants.NO_SECURITY) {
                return true;
            }

            /*
            * For every action we need a username, so get this now. The username
            * defined in the deployment descriptor takes precedence.
            */
            reqData.setUsername((String) getOption(WSHandlerConstants.USER));
            if (reqData.getUsername() == null || reqData.getUsername().equals("")) {
                reqData.setUsername((String) mc.getProperty(WSHandlerConstants.USER));
                mc.setProperty(WSHandlerConstants.USER, null);
            }

            /*
            * Now we perform some set-up for UsernameToken and Signature
            * functions. No need to do it for encryption only. Check if username
            * is available and then get a password.
            */
            if (((doAction & (WSConstants.SIGN | WSConstants.UT | WSConstants.UT_SIGN)) != 0)
                    && (reqData.getUsername() == null || reqData.getUsername().equals(""))) {
                /*
                * We need a username - if none throw an JAXRPCException. For encryption
                * there is a specific parameter to get a username.
                */
                throw new JAXRPCException("WSS4JHandler: Empty username for specified action");
            }
            if (doDebug) {
                log.debug("Action: " + doAction);
                log.debug("Actor: " + reqData.getActor());
            }
            /*
            * Now get the SOAP part from the request message and convert it into a
            * Document.
            *
            * This forces Axis to serialize the SOAP request into FORM_STRING.
            * This string is converted into a document.
            *
            * During the FORM_STRING serialization Axis performs multi-ref of
            * complex data types (if requested), generates and inserts references
            * for attachments and so on. The resulting Document MUST be the
            * complete and final SOAP request as Axis would send it over the wire.
            * Therefore this must shall be the last (or only) handler in a chain.
            *
            * Now we can perform our security operations on this request.
            */
            Document doc = null;
            SOAPMessage message = ((SOAPMessageContext) mc).getMessage();
            Boolean propFormOptimization = (Boolean) mc.getProperty("axis.form.optimization");
            log.debug("Form optimization: " + propFormOptimization);
            /*
            * If the message context property contains a document then this is a
            * chained handler.
            */
            SOAPPart sPart = message.getSOAPPart();
            if ((doc = (Document) mc.getProperty(SECURED_DOCUMENT)) == null) {
                try {
                    doc = messageToDocument(message);
                } catch (Exception e) {
                    if (doDebug) {
                        log.debug(e.getMessage(), e);
                    }
                    throw new JAXRPCException("WSS4JHandler: cannot get SOAP envlope from message", e);
                }
            }
            if (doDebug) {
                log.debug("WSS4JHandler: orginal SOAP request: ");
                log.debug(org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc));
            }
            doSenderAction(doAction, doc, reqData, actions, isRequest);

            /*
            * If required convert the resulting document into a message first. The
            * outputDOM() method performs the necessary c14n call. After that we
            * extract it as a string for further processing.
            *
            * Set the resulting byte array as the new SOAP message.
            *
            * If noSerialization is false, this handler shall be the last (or only)
            * one in a handler chain. If noSerialization is true, just set the
            * processed Document in the transfer property. The next Axis WSS4J
            * handler takes it and performs additional security processing steps.
            *
            */
            if (reqData.isNoSerialization()) {
                mc.setProperty(SECURED_DOCUMENT, doc);
            } else {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                XMLUtils.outputDOM(doc, os, true);
                if (doDebug) {
                    String osStr = null;
                    try {
                        osStr = os.toString("UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        if (doDebug) {
                            log.debug(e.getMessage(), e);
                        }
                        osStr = os.toString();
                    }
                    log.debug("Send request:");
                    log.debug(osStr);
                }

                try {
                    sPart.setContent(new StreamSource(new ByteArrayInputStream(os.toByteArray())));
                } catch (SOAPException se) {
                    if (doDebug) {
                        log.debug(se.getMessage(), se);
                    }
                    throw new JAXRPCException("Couldn't set content on SOAPPart" + se.getMessage(), se);
                }
                mc.setProperty(SECURED_DOCUMENT, null);
            }
            if (doDebug) {
                log.debug("WSS4JHandler: exit invoke()");
            }
            return true;
        }

        @SuppressWarnings("unchecked")
        public boolean doReceiver(MessageContext mc, RequestData reqData, boolean isRequest) throws org.apache.ws.security.WSSecurityException {
            Vector actions = new Vector();
            String action = (String) getOption(WSHandlerConstants.ACTION);
            if (action == null) {
                action = (String) mc.getProperty(WSHandlerConstants.ACTION);
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
            //if ((doAction & (WSConstants.ENCR | WSConstants.UT | WSConstants.UT_SIGN)) != 0) {
            cbHandler = getPasswordCallbackHandler(reqData);
            //}
            reqData.setCallbackHandler(cbHandler);

            /*
            * Get and check the Signature specific parameters first because they
            * may be used for encryption too.
            */
            doReceiverAction(doAction, reqData);

            Element elem = WSSecurityUtil.getSecurityHeader(doc, actor);

            List wsResult = null;
            try {
                wsResult =
                        secEngine.processSecurityHeader(elem, reqData);
            } catch (org.apache.ws.security.WSSecurityException ex) {
                if (doDebug) {
                    log.debug(ex.getMessage(), ex);
                }
                throw new JAXRPCException("WSS4JHandler: security processing failed",
                        ex);
            }
            if (wsResult == null || wsResult.size() == 0) {         // no security header found
                if (doAction == WSConstants.NO_SECURITY) {
                    return true;
                } else {
                    throw new JAXRPCException("WSS4JHandler: Request does not contain required Security header");
                }
            }
            if (reqData.getWssConfig().isEnableSignatureConfirmation() && !isRequest) {
                checkSignatureConfirmation(reqData, wsResult);
            }

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

/*
            if (actionResult != null) {
                X509Certificate returnCert =
                        (X509Certificate) actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);

                if (returnCert != null && !verifyTrust(returnCert, reqData)) {
                    throw new JAXRPCException("WSS4JHandler: The certificate used for the signature is not trusted");
                }
            }
*/

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

/*
            if (actionResult != null) {
                Timestamp timestamp =
                        (Timestamp) actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);

                if (timestamp != null && reqData.getWssConfig().isTimeStampStrict()
                        && !verifyTimestamp(timestamp, decodeTimeToLive(reqData))) {
                    throw new JAXRPCException("WSS4JHandler: The timestamp could not be validated");
                }
            }
*/

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

        protected boolean checkReceiverResults(
                List<WSSecurityEngineResult> wsResult, List<Integer> actions
        ) {
            List<WSSecurityEngineResult> wsSecurityEngineResults = new ArrayList<WSSecurityEngineResult>();
            for (WSSecurityEngineResult result : wsResult) {
                boolean found = false;
                for (WSSecurityEngineResult res : wsSecurityEngineResults) {
                    if (((Integer) result.get(WSSecurityEngineResult.TAG_ACTION)).equals((Integer) res.get(WSSecurityEngineResult.TAG_ACTION))) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    wsSecurityEngineResults.add(result);
                }
            }
            int size = actions.size();
            int ai = 0;
            for (WSSecurityEngineResult result : wsSecurityEngineResults) {
                final Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
                int act = actInt.intValue();
                if (act == WSConstants.SC || act == WSConstants.BST || act == WSConstants.DKT || act == WSConstants.SCT || act == WSConstants.UT_NOPASSWORD) {
                    continue;
                }

                if (ai >= size || actions.get(ai++).intValue() != act) {
                    return false;
                }
            }
/*
        if (ai != size) {
            return false;
        }
*/
            return true;
        }

        protected boolean checkReceiverResultsAnyOrder(
                List<WSSecurityEngineResult> wsResult, List<Integer> actions
        ) {
            List<Integer> recordedActions = new ArrayList<Integer>(actions.size());
            for (Integer action : actions) {
                recordedActions.add(action);
            }

            for (WSSecurityEngineResult result : wsResult) {
                final Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
                int act = actInt.intValue();
                if (act == WSConstants.SC || act == WSConstants.BST) {
                    continue;
                }

                if (!recordedActions.remove(actInt)) {
                    if (actInt == 8192) {
                        if (!recordedActions.remove(new Integer(1))) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }

            return recordedActions.isEmpty();
        }

        /**
         * Utility method to convert SOAPMessage to org.w3c.dom.Document
         */
        public Document messageToDocument(SOAPMessage message) {
            try {
                Source content = message.getSOAPPart().getContent();
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder builder = dbf.newDocumentBuilder();
                return builder.parse(org.apache.ws.security.util.XMLUtils.sourceToInputSource(content));
            } catch (Exception ex) {
                throw new JAXRPCException("messageToDocument: cannot convert SOAPMessage into Document", ex);
            }
        }

        public Object getOption(String key) {
            return handlerInfo.getHandlerConfig().get(key);
        }

        public Object getProperty(Object msgContext, String key) {
            return ((MessageContext) msgContext).getProperty(key);
        }

        public void setProperty(Object msgContext, String key, Object value) {
            ((MessageContext) msgContext).setProperty(key, value);
        }

        public String getPassword(Object msgContext) {
            return (String) ((MessageContext) msgContext).getProperty(Call.PASSWORD_PROPERTY);
        }

        public void setPassword(Object msgContext, String password) {
            ((MessageContext) msgContext).setProperty(Call.PASSWORD_PROPERTY, password);
        }
    }

    protected class TestSecurityEventListener implements SecurityEventListener {
        private int eventNr = 0;
        private SecurityEvent.Event[] expectedEvents;

        public TestSecurityEventListener(SecurityEvent.Event[] expectedEvents) {
            this.expectedEvents = expectedEvents;
        }

        @Override
        public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
            Assert.assertEquals(securityEvent.getSecurityEventType(), expectedEvents[eventNr++]);
        }
    }
}
