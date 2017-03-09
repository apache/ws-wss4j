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
package org.apache.wss4j.performance;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.stax.ConfigurationConverter;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.processor.input.DecryptInputProcessor;
import org.apache.wss4j.stax.test.WSS4JCallbackHandlerImpl;
import org.apache.wss4j.stax.test.utils.SOAPUtil;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.impl.InboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.processor.input.AbstractDecryptInputProcessor;
import org.apache.xml.security.stax.impl.processor.input.AbstractSignatureReferenceVerifyInputProcessor;
import org.apache.xml.security.stax.impl.processor.input.XMLEventReaderInputProcessor;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.junit.AfterClass;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

public abstract class AbstractTestBase extends org.junit.Assert {

    //javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
    //transformer.transform(new StreamSource(new ByteArrayInputStream(baos.toByteArray())), new StreamResult(System.out));

    protected static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    protected static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
    protected DocumentBuilderFactory documentBuilderFactory;

    protected static final String SECURED_DOCUMENT = "securedDocument";

    static {
        LogManager.getLogManager().addLogger(Logger.getLogger("org.jcp.xml.dsig.internal.dom"));
        LogManager.getLogManager().getLogger("org.jcp.xml.dsig.internal.dom").setLevel(Level.FINE);
        WSSConfig.init();
    }

    @AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
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

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), null);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream,
                                      SecurityEventListener securityEventListener)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, InputStream inputStream,
                                      List<SecurityEvent> securityEventList, SecurityEventListener securityEventListener)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(inputStream), securityEventList, securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlStreamReader, null);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader,
                                      SecurityEventListener securityEventListener)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        return doInboundSecurity(securityProperties, xmlStreamReader, new ArrayList<>(), securityEventListener);
    }

    public Document doInboundSecurity(WSSSecurityProperties securityProperties, XMLStreamReader xmlStreamReader,
                                      List<SecurityEvent> securityEventList, SecurityEventListener securityEventListener)
            throws XMLStreamException, ParserConfigurationException, XMLSecurityException {
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader outXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader, securityEventList, securityEventListener);
        return StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), outXmlStreamReader);
    }

    protected ByteArrayOutputStream doOutboundSecurity(WSSSecurityProperties securityProperties, InputStream sourceDocument)
            throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        return baos;
    }

    protected ByteArrayOutputStream doOutboundSecurity(Map<String, Object> config, InputStream sourceDocument)
        throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        return baos;
    }

    protected Document doOutboundSecurityWithWSS4J(InputStream sourceDocument, String action, Properties properties)
            throws WSSecurityException, TransformerException {
        Map<String, Object> context = doOutboundSecurityWithWSS4J_1(sourceDocument, action, properties);
        return (Document) context.get(SECURED_DOCUMENT);
    }

    protected Map<String, Object> doOutboundSecurityWithWSS4J_1(
            InputStream sourceDocument, String action, final Properties properties
    ) throws WSSecurityException, TransformerException {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        final Map<String, Object> messageContext = getMessageContext(sourceDocument);
        messageContext.put(WSHandlerConstants.ACTION, action);
        messageContext.put(WSHandlerConstants.USER, "transmitter");

        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", "transmitter.jks");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.put(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.put("" + sigProperties.hashCode(), sigProperties);

        Properties encProperties = new Properties();
        encProperties.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        encProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", "transmitter.jks");
        encProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", "default");
        //sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.alias", "transmitter");
        wss4JHandler.setPassword(messageContext, "default");
        messageContext.put(WSHandlerConstants.ENCRYPTION_USER, "receiver");
        messageContext.put(WSHandlerConstants.ENC_PROP_REF_ID, "" + encProperties.hashCode());
        messageContext.put("" + encProperties.hashCode(), encProperties);

        Enumeration<?> enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.put(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        requestData.setCallbackHandler(new WSS4JCallbackHandlerImpl());
        requestData.setWssConfig(WSSConfig.getNewInstance());

        wss4JHandler.doSender(messageContext, requestData, true);

        return messageContext;
    }

    protected Document doInboundSecurityWithWSS4J(Document document, String action) throws Exception {
        Map<String, Object> messageContext = doInboundSecurityWithWSS4J_1(document, action);
        return ((Document) messageContext.get(SECURED_DOCUMENT));
    }

    protected Map<String, Object> doInboundSecurityWithWSS4J_1(Document document, String action) throws Exception {
        return doInboundSecurityWithWSS4J_1(document, action, new Properties(), false);
    }

    protected Map<String, Object> doInboundSecurityWithWSS4J_1(
            Document document, String action, Properties properties, boolean client
    ) throws Exception {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        Map<String, Object> messageContext = getMessageContext(document);
        messageContext.put(WSHandlerConstants.ACTION, action);
        if (client) {
            messageContext.put(WSHandlerConstants.USER, "transmitter");
        } else {
            messageContext.put(WSHandlerConstants.USER, "receiver");
        }

        if (properties.get(WSHandlerConstants.PW_CALLBACK_REF) != null) {
            messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, properties.get(WSHandlerConstants.PW_CALLBACK_REF));
        } else {
            messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, new WSS4JCallbackHandlerImpl());
        }

        messageContext.put(WSHandlerConstants.VALIDATE_SAML_SUBJECT_CONFIRMATION, "false");
        Enumeration<?> enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.put(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);
        if (client) {
            final Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            requestData.setDecCrypto(crypto);
            requestData.setSigVerCrypto(crypto);
        } else {
            final Crypto crypto = CryptoFactory.getInstance("receiver-crypto.properties");
            requestData.setDecCrypto(crypto);
            requestData.setSigVerCrypto(crypto);
        }

        if (properties.get(WSHandlerConstants.ALLOW_USERNAMETOKEN_NOPASSWORD) != null) {
            messageContext.put(WSHandlerConstants.ALLOW_USERNAMETOKEN_NOPASSWORD,
                               properties.get(WSHandlerConstants.ALLOW_USERNAMETOKEN_NOPASSWORD));
        } else if (WSHandlerConstants.USERNAME_TOKEN_SIGNATURE.equals(action)) {
            messageContext.put(WSHandlerConstants.ALLOW_USERNAMETOKEN_NOPASSWORD, "true");
        }

        // Disable PrefixList checking as the stax code doesn't support this yet
        //todo
        List<BSPRule> ignoredRules = new ArrayList<>();
        ignoredRules.add(BSPRule.R5404);
        ignoredRules.add(BSPRule.R5406);
        ignoredRules.add(BSPRule.R5407);
        ignoredRules.add(BSPRule.R5417);
        ignoredRules.add(BSPRule.R3063);
        ignoredRules.add(BSPRule.R5620);
        ignoredRules.add(BSPRule.R5621);
        //ignoredRules.add(BSPRule.R5215);
        requestData.setIgnoredBSPRules(ignoredRules);

        wss4JHandler.doReceiver(messageContext, requestData, false);

        return messageContext;
    }

    protected Map<String, Object> getMessageContext(InputStream inputStream) {
        Map<String, Object> context = new HashMap<>();
        try {
            context.put(SECURED_DOCUMENT, SOAPUtil.toSOAPPart(inputStream));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return context;
    }

    private Map<String, Object> getMessageContext(Document document) {
        Map<String, Object> context = new HashMap<>();
        context.put(SECURED_DOCUMENT, document);
        return context;
    }

    protected XPathExpression getXPath(String expression) throws XPathExpressionException {
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xPath = xPathFactory.newXPath();
        xPath.setNamespaceContext(
                new NamespaceContext() {
                    @Override
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
                        } else if (WSSConstants.PREFIX_XENC11.equals(prefix)) {
                            return WSSConstants.NS_XMLENC11;
                        } else {
                            return null;
                        }
                    }

                    @Override
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
                        } else if (WSSConstants.NS_XMLENC11.equals(namespaceURI)) {
                            return WSSConstants.PREFIX_XENC11;
                        } else {
                            return null;
                        }
                    }

                    @Override
                    public Iterator<String> getPrefixes(String namespaceURI) {
                        return null;
                    }
                }
        );
        return xPath.compile(expression);
    }

    class CustomWSS4JHandler extends WSHandler {

        private final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(CustomWSS4JHandler.class.getName());
        private final boolean doDebug = LOG.isDebugEnabled();

        /**
         * Handles incoming web service requests and outgoing responses
         *
         * @throws TransformerException
         */
        public boolean doSender(Map<String, Object> mc, RequestData reqData, boolean isRequest)
                throws WSSecurityException, TransformerException {

            /*
             * Get the action first.
             */
            String action = (String) mc.get(WSHandlerConstants.ACTION);
            if (action == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", "WSS4JHandler: No action defined");
            }
            List<HandlerAction> actions = WSSecurityUtil.decodeHandlerAction(action, null);
            if (actions.isEmpty()) {
                return true;
            }

            /*
            * For every action we need a username, so get this now. The username
            * defined in the deployment descriptor takes precedence.
            */
            reqData.setUsername((String) getOption(WSHandlerConstants.USER));
            if (reqData.getUsername() == null || reqData.getUsername().equals("")) {
                reqData.setUsername((String) mc.get(WSHandlerConstants.USER));
            }

            /*
            * Now we perform some set-up for UsernameToken and Signature
            * functions. No need to do it for encryption only. Check if username
            * is available and then get a password.
            */
            boolean usernameRequired = false;
            for (HandlerAction handlerAction : actions) {
                if (handlerAction.getAction() == WSConstants.SIGN
                    || handlerAction.getAction() == WSConstants.UT
                    || handlerAction.getAction() == WSConstants.UT_SIGN) {
                    usernameRequired = true;
                    break;
                }
            }
            if (usernameRequired && (reqData.getUsername() == null || reqData.getUsername().equals(""))) {
                /*
                 * We need a username - if none throw a WSSecurityException. For encryption
                 * there is a specific parameter to get a username.
                 */
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                        "WSS4JHandler: Empty username for specified action"
                );
            }
            if (doDebug) {
                LOG.debug("Actor: " + reqData.getActor());
            }
            /*
            * Now get the SOAP part from the request message and convert it into a
            * Document.
            *
            * Now we can perform our security operations on this request.
            */
            Document doc = (Document) mc.get(SECURED_DOCUMENT);
            if (doc == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                        "WSS4JHandler: cannot get SOAP envlope from message"
                );
            }
            if (doDebug) {
                LOG.debug("WSS4JHandler: orginal SOAP request: ");
                LOG.debug(XMLUtils.prettyDocumentToString(doc));
            }
            doSenderAction(doc, reqData, actions, isRequest);

            mc.put(SECURED_DOCUMENT, doc);

            return true;
        }

        @SuppressWarnings("unchecked")
        public boolean doReceiver(Map<String, Object> mc, RequestData reqData, boolean isRequest)
                throws WSSecurityException {
            String action = (String) mc.get(WSHandlerConstants.ACTION);
            if (action == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", "WSS4JHandler: No action defined");
            }
            List<Integer> actions = WSSecurityUtil.decodeAction(action);

            String actor = (String) mc.get(WSHandlerConstants.ACTOR);

            Document doc = (Document) mc.get(SECURED_DOCUMENT);

            /*
             * Check if it's a fault. Don't process faults.
             */
            org.apache.wss4j.dom.SOAPConstants soapConstants =
                    WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
            if (WSSecurityUtil.findElement(
                doc.getDocumentElement(), "Fault", soapConstants.getEnvelopeURI()) != null
            ) {
                return false;
            }

            /*
             * To check a UsernameToken or to decrypt an encrypted message we need
             * a password.
             */
            CallbackHandler cbHandler = getPasswordCallbackHandler(reqData);
            reqData.setCallbackHandler(cbHandler);

            /*
             * Get and check the Signature specific parameters first because they
             * may be used for encryption too.
             */
            doReceiverAction(actions, reqData);

            Element elem = WSSecurityUtil.getSecurityHeader(doc, actor);

            List<WSSecurityEngineResult> wsResult = null;
            try {
                wsResult = secEngine.processSecurityHeader(elem, reqData);
            } catch (WSSecurityException ex) {
                if (doDebug) {
                    LOG.debug(ex.getMessage(), ex);
                }
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                        "WSS4JHandler: security processing failed", ex
                );
            }
            if (wsResult == null || wsResult.isEmpty()) {
                // no security header found
                if (actions.isEmpty()) {
                    return true;
                } else {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "empty",
                            "WSS4JHandler: Request does not contain required Security header"
                    );
                }
            }
            if (reqData.getWssConfig().isEnableSignatureConfirmation() && !isRequest) {
                checkSignatureConfirmation(reqData, wsResult);
            }

            if (doDebug) {
                LOG.debug("Processed received SOAP request");
            }

            /*
             * now check the security actions: do they match, in right order?
             */
            if (!checkReceiverResults(wsResult, actions)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                        "WSS4JHandler: security processing failed (actions mismatch)"
                );
            }

            /*
             * All ok up to this point. Now construct and setup the
             * security result structure. The service may fetch this
             * and check it.
             */
            List<WSHandlerResult> results = null;
            if ((results = (List<WSHandlerResult>) mc.get(WSHandlerConstants.RECV_RESULTS)) == null) {
                results = new ArrayList<>();
                mc.put(WSHandlerConstants.RECV_RESULTS, results);
            }
            WSHandlerResult rResult = new WSHandlerResult(actor, wsResult);
            results.add(0, rResult);
            if (doDebug) {
                LOG.debug("WSS4JHandler: exit invoke()");
            }

            return true;
        }

        @Override
        protected boolean checkReceiverResults(
                List<WSSecurityEngineResult> wsResult, List<Integer> actions
        ) {
            List<WSSecurityEngineResult> wsSecurityEngineResults = new ArrayList<>();
            for (WSSecurityEngineResult result : wsResult) {
                boolean found = false;
                for (WSSecurityEngineResult res : wsSecurityEngineResults) {
                    if (result.get(WSSecurityEngineResult.TAG_ACTION).equals(res.get(WSSecurityEngineResult.TAG_ACTION))) {
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
                final Integer act = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
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

        @Override
        public Object getOption(String key) {
            return null;
        }

        @SuppressWarnings("unchecked")
        @Override
        public Object getProperty(Object msgContext, String key) {
            return ((Map<String, Object>) msgContext).get(key);
        }

        @SuppressWarnings("unchecked")
        @Override
        public void setProperty(Object msgContext, String key, Object value) {
            ((Map<String, Object>) msgContext).put(key, value);
        }

        @SuppressWarnings("unchecked")
        @Override
        public String getPassword(Object msgContext) {
            return (String) ((Map<String, Object>) msgContext).get("password");
        }

        @SuppressWarnings("unchecked")
        @Override
        public void setPassword(Object msgContext, String password) {
            ((Map<String, Object>) msgContext).put("password", password);
        }
    }

    protected class TestSecurityEventListener implements SecurityEventListener {
        private SecurityEventConstants.Event[] expectedEvents;
        private List<SecurityEvent> receivedSecurityEvents = new ArrayList<>();

        public TestSecurityEventListener(SecurityEventConstants.Event[] expectedEvents) {
            this.expectedEvents = expectedEvents;
        }

        public List<SecurityEvent> getReceivedSecurityEvents() {
            return receivedSecurityEvents;
        }

        @SuppressWarnings("unchecked")
        public <T> T getSecurityEvent(SecurityEventConstants.Event securityEvent) {
            for (SecurityEvent event : receivedSecurityEvents) {
                if (event.getSecurityEventType() == securityEvent) {
                    return (T) event;
                }
            }
            return null;
        }

        @SuppressWarnings("unchecked")
        public <T> List<T> getSecurityEvents(SecurityEventConstants.Event securityEvent) {
            List<T> foundEvents = new ArrayList<>();
            for (SecurityEvent event : receivedSecurityEvents) {
                if (event.getSecurityEventType() == securityEvent) {
                    foundEvents.add((T) event);
                }
            }
            return foundEvents;
        }

        @Override
        public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
            Assert.assertNotNull(securityEvent.getCorrelationID());
            Assert.assertNotEquals("", securityEvent.getCorrelationID());
            receivedSecurityEvents.add(securityEvent);
        }

        public void compare() {
            if (expectedEvents.length != receivedSecurityEvents.size()) {
                printEvents();
                Assert.fail("event count mismatch");
            }
            boolean asserted = true;
            for (int i = 0; i < expectedEvents.length; i++) {
                if (!expectedEvents[i].equals(receivedSecurityEvents.get(i).getSecurityEventType())) {
                    asserted = false;
                    break;
                }
            }
            if (!asserted) {
                printEvents();
                Assert.fail("event mismatch");
            }
        }

        private void printEvents() {
            System.out.println("expected events:");
            for (int i = 0; i < expectedEvents.length; i++) {
                SecurityEventConstants.Event expectedEvent = expectedEvents[i];
                System.out.println("WSSecurityEventConstants." + expectedEvent + ",");
            }
            System.out.println("received events:");
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                System.out.println("WSSecurityEventConstants." + securityEvent.getSecurityEventType() + ",");
            }
        }
    }

    //sometimes I really like reflection. We can fix jdk bugs which will never be fixed, we can do other funny things and
    //we can also change "private static final" fields for testing:-)
    //But keep in mind that this only works for Objects and not primitive types. Primitive types will be inlined...
    public static void switchAllowNotSameDocumentReferences(Boolean value) throws NoSuchFieldException, IllegalAccessException {

        Field field = AbstractSignatureReferenceVerifyInputProcessor.class.getDeclaredField("allowNotSameDocumentReferences");
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        field.set(null, value);
    }

    public static void switchDoNotThrowExceptionForManifests(Boolean value) throws NoSuchFieldException, IllegalAccessException {
        Field field = AbstractSignatureReferenceVerifyInputProcessor.class.getDeclaredField("doNotThrowExceptionForManifests");
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        field.set(null, value);
    }

    public static int changeValueOfMaximumAllowedReferencesPerManifest(Integer value) throws NoSuchFieldException, IllegalAccessException {
        Field field = AbstractSignatureReferenceVerifyInputProcessor.class.getDeclaredField("maximumAllowedReferencesPerManifest");
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        Integer oldval = (Integer)field.get(null);
        field.set(null, value);
        return oldval;
    }

    public static int changeValueOfMaximumAllowedTransformsPerReference(Integer value) throws NoSuchFieldException, IllegalAccessException {
        Field field = AbstractSignatureReferenceVerifyInputProcessor.class.getDeclaredField("maximumAllowedTransformsPerReference");
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        Integer oldval = (Integer)field.get(null);
        field.set(null, value);
        return oldval;
    }

    public static void switchAllowMD5Algorithm(Boolean value) throws NoSuchFieldException, IllegalAccessException {
        Field field = InboundSecurityContextImpl.class.getDeclaredField("allowMD5Algorithm");
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        field.set(null, value);
    }

    public static int changeValueOfMaximumAllowedXMLStructureDepth(Integer value) throws NoSuchFieldException, IllegalAccessException {
        Field xmlEventReaderInputProcessorField = XMLEventReaderInputProcessor.class.getDeclaredField("maximumAllowedXMLStructureDepth");
        xmlEventReaderInputProcessorField.setAccessible(true);
        Field abstractDecryptInputProcessorField = AbstractDecryptInputProcessor.class.getDeclaredField("maximumAllowedXMLStructureDepth");
        abstractDecryptInputProcessorField.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(xmlEventReaderInputProcessorField, xmlEventReaderInputProcessorField.getModifiers() & ~Modifier.FINAL);
        modifiersField.setInt(abstractDecryptInputProcessorField, abstractDecryptInputProcessorField.getModifiers() & ~Modifier.FINAL);

        Integer oldval = (Integer)xmlEventReaderInputProcessorField.get(null);
        xmlEventReaderInputProcessorField.set(null, value);
        abstractDecryptInputProcessorField.set(null, value);
        return oldval;
    }

    public static long changeValueOfMaximumAllowedDecompressedBytes(Long value) throws NoSuchFieldException, IllegalAccessException {
        Field field = DecryptInputProcessor.class.getDeclaredField("maximumAllowedDecompressedBytes");
        field.setAccessible(true);

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        Long oldval = (Long) field.get(null);
        field.set(null, value);
        return oldval;
    }

    public static Double getJavaSpecificationVersion() {
        String jsv = System.getProperty("java.specification.version");
        if (jsv != null) {
            return Double.parseDouble(jsv);
        }
        return 0.0d;
    }
}
