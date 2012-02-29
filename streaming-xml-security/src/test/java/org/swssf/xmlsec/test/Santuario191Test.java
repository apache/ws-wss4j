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
package org.swssf.xmlsec.test;

import org.swssf.xmlsec.impl.transformer.canonicalizer.Canonicalizer11_OmitCommentsTransformer;
import org.swssf.xmlsec.test.utils.XMLEventNSAllocator;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;

import static org.testng.Assert.assertEquals;

/**
 * This is a test for Santuario-191:
 * <p/>
 * https://issues.apache.org/jira/browse/SANTUARIO-191
 * <p/>
 * An xml:Id attribute is appearing in a child element, contrary to the C14n11 spec.
 */
public class Santuario191Test {

    private static final String INPUT_DATA =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<test xml:id=\"testid1\">"
                    + "<data>"
                    + "    <user1>Alice</user1>"
                    + "    <user2>Bob</user2>"
                    + "</data>"
                    + "</test>";
    private static final String EXPECTED_RESULT =
            "<data>"
                    + "    <user1>Alice</user1>"
                    + "    <user2>Bob</user2>"
                    + "</data>";

    private XMLInputFactory xmlInputFactory;

    @BeforeMethod
    public void setUp() throws Exception {
        this.xmlInputFactory = XMLInputFactory.newInstance();
        this.xmlInputFactory.setEventAllocator(new XMLEventNSAllocator());
    }

    @Test
    public void testSantuario191() throws Exception {
        //
        // Parse the Data
        //
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Canonicalizer11_OmitCommentsTransformer c =
                new Canonicalizer11_OmitCommentsTransformer(null, baos);
        XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(
                new StringReader(INPUT_DATA)
        );

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = xmlEventReader.nextEvent();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(new QName(null, "data"))) {
                break;
            }
        }

        while (xmlEventReader.hasNext()) {
            c.transform(xmlEvent);
            if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(new QName(null, "data"))) {
                break;
            }
            xmlEvent = xmlEventReader.nextEvent();
        }

        assertEquals(new String(baos.toByteArray()), EXPECTED_RESULT);
    }

}
