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
package org.apache.wss4j.common.util;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.XMLCipherUtil;
import org.apache.xml.security.stax.impl.util.MultiInputStream;
import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import jakarta.mail.internet.MimeUtility;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public final class AttachmentUtils {

    public static final String MIME_HEADER_CONTENT_DESCRIPTION = "Content-Description";
    public static final String MIME_HEADER_CONTENT_DISPOSITION = "Content-Disposition";
    public static final String MIME_HEADER_CONTENT_ID = "Content-ID";
    public static final String MIME_HEADER_CONTENT_LOCATION = "Content-Location";
    public static final String MIME_HEADER_CONTENT_TYPE = "Content-Type";

    public static final char DOUBLE_QUOTE = '"';
    public static final char SINGLE_QUOTE = '\'';
    public static final char LEFT_PARENTHESIS = '(';
    public static final char RIGHT_PARENTHESIS = ')';
    public static final char CARRIAGE_RETURN = '\r';
    public static final char LINEFEED = '\n';
    public static final char SPACE = ' ';
    public static final char HTAB = '\t';
    public static final char EQUAL = '=';
    public static final char ASTERISK = '*';
    public static final char SEMICOLON = ';';
    public static final char BACKSLASH = '\\';

    public static final String PARAM_CHARSET = "charset";
    public static final String PARAM_CREATION_DATE = "creation-date";
    public static final String PARAM_FILENAME = "filename";
    public static final String PARAM_MODIFICATION_DATE = "modification-date";
    public static final String PARAM_PADDING = "padding";
    public static final String PARAM_READ_DATE = "read-date";
    public static final String PARAM_SIZE = "size";
    public static final String PARAM_TYPE = "type";

    public static final Set<String> ALL_PARAMS = new HashSet<>();

    static {
        ALL_PARAMS.add(PARAM_CHARSET);
        ALL_PARAMS.add(PARAM_CREATION_DATE);
        ALL_PARAMS.add(PARAM_FILENAME);
        ALL_PARAMS.add(PARAM_MODIFICATION_DATE);
        ALL_PARAMS.add(PARAM_PADDING);
        ALL_PARAMS.add(PARAM_READ_DATE);
        ALL_PARAMS.add(PARAM_SIZE);
        ALL_PARAMS.add(PARAM_TYPE);
    }

    private AttachmentUtils() {
        // complete
    }

    public static void canonizeMimeHeaders(OutputStream os, Map<String, String> headers) throws IOException {
        //5.4.1 MIME header canonicalization:

        //3. sorting
        Map<String, String> sortedHeaders = new TreeMap<>();
        Iterator<Map.Entry<String, String>> iterator = headers.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, String> next = iterator.next();
            String name = next.getKey();
            String value = next.getValue();

            //2. only listed headers; 4. case
            if (MIME_HEADER_CONTENT_DESCRIPTION.equalsIgnoreCase(name)) {
                sortedHeaders.put(MIME_HEADER_CONTENT_DESCRIPTION,
                        //9. uncomment
                        uncomment(
                                //6. decode
                                MimeUtility.decodeText(
                                        //5. unfold
                                        MimeUtility.unfold(value)
                                )
                        )
                );
            } else if (MIME_HEADER_CONTENT_DISPOSITION.equalsIgnoreCase(name)) {
                sortedHeaders.put(MIME_HEADER_CONTENT_DISPOSITION,
                        decodeRfc2184(
                                //9. uncomment
                                uncomment(
                                        //8. unfold ws
                                        unfoldWhitespace(
                                                //5. unfold
                                                MimeUtility.unfold(value)
                                        )
                                )
                        )
                );
            } else if (MIME_HEADER_CONTENT_ID.equalsIgnoreCase(name)) {
                sortedHeaders.put(MIME_HEADER_CONTENT_ID,
                        //9. uncomment
                        uncomment(
                                //8. unfold ws
                                unfoldWhitespace(
                                        //5. unfold
                                        MimeUtility.unfold(value)
                                )
                        )
                );
            } else if (MIME_HEADER_CONTENT_LOCATION.equalsIgnoreCase(name)) {
                sortedHeaders.put(MIME_HEADER_CONTENT_LOCATION,
                        //9. uncomment
                        uncomment(
                                //8. unfold ws
                                unfoldWhitespace(
                                        //5. unfold
                                        MimeUtility.unfold(value)
                                )
                        )
                );
            } else if (MIME_HEADER_CONTENT_TYPE.equalsIgnoreCase(name)) {
                sortedHeaders.put(MIME_HEADER_CONTENT_TYPE,
                        decodeRfc2184(
                                //9. uncomment
                                uncomment(
                                        //8. unfold ws
                                        unfoldWhitespace(
                                                //5. unfold
                                                MimeUtility.unfold(value)
                                        )
                                )
                        )
                );
            }
        }
        //2. default content-type
        if (!sortedHeaders.containsKey(MIME_HEADER_CONTENT_TYPE)) {
            sortedHeaders.put(MIME_HEADER_CONTENT_TYPE, "text/plain;charset=\"us-ascii\"");
        }

        OutputStreamWriter outputStreamWriter = new OutputStreamWriter(os, StandardCharsets.UTF_8);

        Iterator<Map.Entry<String, String>> entryIterator = sortedHeaders.entrySet().iterator();
        while (entryIterator.hasNext()) {
            Map.Entry<String, String> next = entryIterator.next();
            String name = next.getKey();
            String value = next.getValue();

            //12.
            outputStreamWriter.write(name);
            outputStreamWriter.write(':');
            outputStreamWriter.write(value);
            //18. CRLF pair
            if (!value.endsWith("\r\n")) {
                outputStreamWriter.write("\r\n");
            }
        }
        outputStreamWriter.flush();
    }

    public static String unfoldWhitespace(String text) {
        int count = 0;
        char[] chars = text.toCharArray();
        for (char character : chars) {
            if (SPACE != character && HTAB != character) {
                break;
            }
            count++;
        }
        return text.substring(count, chars.length);
    }

    //removes any CRLF followed by a whitespace
    public static String unfold(final String text) {

        int length = text.length();
        if (length < 3) {
            return text;
        }

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < length - 2; i++) {
            char ch1 = text.charAt(i);
            final char ch2 = text.charAt(i + 1);
            final char ch3 = text.charAt(i + 2);

            if (CARRIAGE_RETURN == ch1 && LINEFEED == ch2 && (SPACE == ch3 || HTAB == ch3)) {

                i += 2;
                if (i >= length - 3) {
                    for (i++; i < length; i++) { //NOPMD
                        stringBuilder.append(text.charAt(i));
                    }
                }
                continue;
            }
            stringBuilder.append(ch1);
            if (i == length - 3) {
                stringBuilder.append(ch2);
                stringBuilder.append(ch3);
            }
        }
        return stringBuilder.toString();
    }

    public static String decodeRfc2184(String text) throws UnsupportedEncodingException {
        if (!text.contains(";")) {
            return text;
        }

        String[] params = text.split(";");
        //first part is the Mime-Header-Value
        StringBuilder stringBuilder = new StringBuilder();
        //10. lower case
        stringBuilder.append(params[0].toLowerCase());

        TreeMap<String, String> paramMap = new TreeMap<>();

        String parameterName = null;
        String parameterValue = null;
        String charset = "us-ascii";
        for (int i = 1; i < params.length; i++) {
            String param = params[i];

            int index = param.indexOf(EQUAL);
            String pName = param.substring(0, index).trim().toLowerCase();
            String pValue = param.substring(index + 1).trim();

            int idx = pName.lastIndexOf(ASTERISK);
            if (idx == pName.length() - 1) {
                //language encoded
                pName = pName.substring(0, pName.length() - 1);

                int charsetIdx = pValue.indexOf(SINGLE_QUOTE);
                if (charsetIdx >= 0) {
                    charset = pValue.substring(0, charsetIdx);
                }
                pValue = pValue.substring(pValue.lastIndexOf(SINGLE_QUOTE) + 1);
                pValue = URLDecoder.decode(pValue, MimeUtility.javaCharset(charset));
            }
            idx = pName.lastIndexOf(ASTERISK);
            if (idx >= 0) {
                //continuation
                //int curr = Integer.parseInt(pName.substring(idx+1).trim());
                String pn = pName.substring(0, idx).trim();
                if (pn.equals(parameterName)) {
                    parameterValue = concatParamValues(parameterValue, pValue);
                } else if (parameterName == null) {
                    parameterName = pn;
                    parameterValue = pValue;
                } else {
                    if (ALL_PARAMS.contains(parameterName)) {
                        parameterValue = parameterValue.toLowerCase();
                    }
                    paramMap.put(parameterName,
                            unquoteInnerText(
                                    quote(parameterValue)
                            )
                    );
                }
            } else {
                if (parameterName != null) {
                    if (ALL_PARAMS.contains(parameterName)) {
                        parameterValue = parameterValue.toLowerCase();
                    }
                    paramMap.put(parameterName,
                            unquoteInnerText(
                                    quote(parameterValue)
                            )
                    );
                    parameterName = null;
                    parameterValue = null;
                }

                if (ALL_PARAMS.contains(pName)) {
                    pValue = pValue.toLowerCase();
                }
                paramMap.put(pName,
                        unquoteInnerText(
                                quote(pValue)
                        )
                );
            }
        }
        if (parameterName != null) {
            if (ALL_PARAMS.contains(parameterName)) {
                parameterValue = parameterValue.toLowerCase();
            }
            paramMap.put(parameterName,
                    unquoteInnerText(
                            quote(parameterValue)
                    )
            );
        }

        Iterator<Map.Entry<String, String>> iterator = paramMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, String> next = iterator.next();
            stringBuilder.append(SEMICOLON);
            stringBuilder.append(next.getKey());
            stringBuilder.append(EQUAL);
            stringBuilder.append(next.getValue());
        }
        return stringBuilder.toString();
    }

    public static String concatParamValues(String a, String b) {
        if (DOUBLE_QUOTE == a.charAt(a.length() - 1)) {
            a = a.substring(0, a.length() - 1);
        }
        if (DOUBLE_QUOTE == b.charAt(0)) {
            b = b.substring(1);
        }
        return a + b;
    }

    public static String quote(String text) {
        char startChar = text.charAt(0);
        char endChar = text.charAt(text.length() - 1);
        if (DOUBLE_QUOTE == startChar && DOUBLE_QUOTE == endChar) {
            return text;
        } else if (DOUBLE_QUOTE != startChar && DOUBLE_QUOTE != endChar) {
            return DOUBLE_QUOTE + text + DOUBLE_QUOTE;
        } else if (DOUBLE_QUOTE != startChar) {
            return DOUBLE_QUOTE + text;
        } else {
            return text + DOUBLE_QUOTE;
        }
    }

    public static String unquoteInnerText(final String text) {
        StringBuilder stringBuilder = new StringBuilder();
        int length = text.length();
        for (int i = 0; i < length - 1; i++) {
            char c = text.charAt(i);
            char c1 = text.charAt(i + 1);
            if (i == 0 && DOUBLE_QUOTE == c) {
                stringBuilder.append(c);
                continue;
            }
            if (BACKSLASH == c && (DOUBLE_QUOTE == c1 || BACKSLASH == c1)) {
                if (i != 0 && i != length - 2) {
                    stringBuilder.append(c);
                }
                stringBuilder.append(c1);
                i++;
            } else if (DOUBLE_QUOTE == c) {
                stringBuilder.append(BACKSLASH);
                stringBuilder.append(c);
            } else if (BACKSLASH == c) {
                stringBuilder.append(c1);
                i++;
            } else {
                stringBuilder.append(c);
                if (i == length - 2 && DOUBLE_QUOTE == c1) {
                    stringBuilder.append(c1);
                }
            }
        }
        return stringBuilder.toString();
    }

    /*
     * Removes any comment outside quoted text. Comments are enclosed between ()
     */
    public static String uncomment(final String text) {
        StringBuilder stringBuilder = new StringBuilder();

        int inComment = 0;
        int length = text.length();
        outer:
        for (int i = 0; i < length; i++) {
            char ch = text.charAt(i);

            if (DOUBLE_QUOTE == ch) {
                stringBuilder.append(ch);
                for (i++; i < length; i++) { //NOPMD
                    ch = text.charAt(i);
                    stringBuilder.append(ch);
                    if (DOUBLE_QUOTE == ch) {
                        continue outer;
                    }
                }
            }
            if (LEFT_PARENTHESIS == ch) {
                inComment++;
                for (i++; i < length; i++) { //NOPMD
                    ch = text.charAt(i);
                    if (LEFT_PARENTHESIS == ch) {
                        inComment++;
                    }
                    if (RIGHT_PARENTHESIS == ch) {
                        inComment--;
                        if (inComment == 0) {
                            continue outer;
                        }
                    }
                }
            }
            stringBuilder.append(ch);
        }
        return stringBuilder.toString();
    }

    public static void readAndReplaceEncryptedAttachmentHeaders(
            Map<String, String> headers, InputStream attachmentInputStream) throws IOException, WSSecurityException {

        //read and replace headers
        List<String> headerLines = new ArrayList<>();
        StringBuilder stringBuilder = new StringBuilder();
        boolean cr = false;
        int ch;
        int lineLength = 0;
        while ((ch = attachmentInputStream.read()) != -1) {
            if (ch == '\r') {
                cr = true;
            } else if (ch == '\n' && cr) {
                cr = false;
                if (lineLength == 1 && stringBuilder.charAt(0) == '\r') {
                    break;
                }
                if (headerLines.size() > 100) {
                    //so much headers? go away....
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILED_CHECK);
                }
                headerLines.add(stringBuilder.substring(0, stringBuilder.length() - 1));
                lineLength = 0;
                stringBuilder.delete(0, stringBuilder.length());
                continue;
            }
            lineLength++;
            //Lines in a message MUST be a maximum of 998 characters excluding the CRLF
            if (lineLength >= 1000) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK);
            }
            stringBuilder.append((char) ch);
        }

        for (String s : headerLines) {
            int idx = s.indexOf(':');
            if (idx == -1) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK);
            }
            headers.put(s.substring(0, idx), s.substring(idx + 1));
        }
    }

    public static InputStream setupAttachmentDecryptionStream(
            final String encAlgo, final Cipher cipher, final Key key, InputStream inputStream)
            throws WSSecurityException {

        CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher) {

            private boolean firstRead = true;

            private void initCipher() throws IOException {
                int ivLen = JCEMapper.getIVLengthFromURI(encAlgo) / 8;
                byte[] ivBytes = new byte[ivLen];

                int read = super.in.read(ivBytes, 0, ivLen);
                while (read != ivLen) {
                    read += super.in.read(ivBytes, read, ivLen - read);
                }

                AlgorithmParameterSpec paramSpec =
                    XMLCipherUtil.constructBlockCipherParameters(encAlgo, ivBytes);

                try {
                    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public int read() throws IOException {
                if (firstRead) {
                    initCipher();
                    firstRead = false;
                }
                return super.read();
            }

            @Override
            public int read(byte[] bytes) throws IOException {
                if (firstRead) {
                    initCipher();
                    firstRead = false;
                }
                return super.read(bytes);
            }

            @Override
            public int read(byte[] bytes, int i, int i2) throws IOException {
                if (firstRead) {
                    initCipher();
                    firstRead = false;
                }
                return super.read(bytes, i, i2);
            }

            @Override
            public long skip(long l) throws IOException {
                if (firstRead) {
                    initCipher();
                    firstRead = false;
                }
                return super.skip(l);
            }

            @Override
            public int available() throws IOException {
                if (firstRead) {
                    initCipher();
                    firstRead = false;
                }
                return super.available();
            }
        };

        return cipherInputStream;
    }

    public static InputStream setupAttachmentEncryptionStream(
            Cipher cipher, boolean complete, Attachment attachment,
            Map<String, String> headers) throws WSSecurityException {

        final InputStream attachmentInputStream;

        if (complete) {
            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                OutputStreamWriter outputStreamWriter = new OutputStreamWriter(byteArrayOutputStream, StandardCharsets.US_ASCII);

                Iterator<Map.Entry<String, String>> iterator = headers.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<String, String> next = iterator.next();
                    String key = next.getKey();
                    String value = next.getValue();
                    //5.5.2 Encryption Processing Rules
                    //When encryption includes MIME headers, only the headers listed in this specification
                    //for the Attachment-Complete-Signature-Transform (Section 5.3.2) are to be included in
                    //the encryption. If a header listed in the profile is present it MUST be included in
                    //the encryption. If a header is not listed in this profile, then it MUST NOT be
                    //included in the encryption.
                    if (AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION.equals(key)
                        || AttachmentUtils.MIME_HEADER_CONTENT_DISPOSITION.equals(key)
                        || AttachmentUtils.MIME_HEADER_CONTENT_ID.equals(key)
                        || AttachmentUtils.MIME_HEADER_CONTENT_LOCATION.equals(key)
                        || AttachmentUtils.MIME_HEADER_CONTENT_TYPE.equals(key)) {
                        iterator.remove();
                        outputStreamWriter.write(key);
                        outputStreamWriter.write(':');
                        outputStreamWriter.write(value);
                        outputStreamWriter.write("\r\n");
                    }
                }
                outputStreamWriter.write("\r\n");
                outputStreamWriter.close();
                attachmentInputStream = new MultiInputStream(
                        new ByteArrayInputStream(byteArrayOutputStream.toByteArray()),
                        attachment.getSourceStream()
                );
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            }
        } else {
            attachmentInputStream = attachment.getSourceStream();
        }

        final ByteArrayInputStream ivInputStream = new ByteArrayInputStream(cipher.getIV());
        final CipherInputStream cipherInputStream = new CipherInputStream(attachmentInputStream, cipher);

        return new MultiInputStream(ivInputStream, cipherInputStream);
    }

    public static byte[] getBytesFromAttachment(
        String xopUri, CallbackHandler attachmentCallbackHandler, boolean removeAttachments
    ) throws WSSecurityException {
        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
        }

        String attachmentId = getAttachmentId(xopUri);

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        attachmentRequestCallback.setAttachmentId(attachmentId);
        attachmentRequestCallback.setRemoveAttachments(removeAttachments);

        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});

            List<Attachment> attachments = attachmentRequestCallback.getAttachments();
            if (attachments == null || attachments.isEmpty()
                || !attachmentId.equals(attachments.get(0).getId())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "empty", new Object[] {"Attachment not found: " + xopUri}
                );
            }
            Attachment attachment = attachments.get(0);
            InputStream inputStream = attachment.getSourceStream();

            return JavaUtils.getBytesFromStream(inputStream);
        } catch (UnsupportedCallbackException | IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public static String getAttachmentId(String xopUri) throws WSSecurityException {
        try {
            return URLDecoder.decode(xopUri.substring("cid:".length()), StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY,
                "empty", new Object[] {"Attachment ID cannot be decoded: " + xopUri}
            );
        }
    }

    public static void storeBytesInAttachment(
        Element parentElement,
        Document doc,
        String attachmentId,
        byte[] bytes,
        CallbackHandler attachmentCallbackHandler
    ) throws WSSecurityException {
        parentElement.setAttributeNS(XMLUtils.XMLNS_NS, "xmlns:xop", WSS4JConstants.XOP_NS);
        Element xopInclude =
            doc.createElementNS(WSS4JConstants.XOP_NS, "xop:Include");
        try {
            xopInclude.setAttributeNS(null, "href", "cid:" + URLEncoder.encode(attachmentId, StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        parentElement.appendChild(xopInclude);

        Attachment resultAttachment = new Attachment();
        resultAttachment.setId(attachmentId);
        resultAttachment.setMimeType("application/ciphervalue");
        resultAttachment.setSourceStream(new ByteArrayInputStream(bytes));

        AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
        attachmentResultCallback.setAttachmentId(attachmentId);
        attachmentResultCallback.setAttachment(resultAttachment);
        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }

    }
}
