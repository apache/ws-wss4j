/*
 * Copyright 1996-2010 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package ch.gigerstyle.xmlsec.test.utils;

import org.apache.cxf.staxutils.AbstractDOMStreamReader;
import org.apache.cxf.staxutils.W3CDOMStreamReader;
import org.w3c.dom.Document;

import javax.xml.stream.XMLInputFactory;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * TODO: class description
 *
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class CustomW3CDOMStreamReader extends W3CDOMStreamReader {

    public CustomW3CDOMStreamReader(Document doc) {
        super(doc);
        try {
            Field field = AbstractDOMStreamReader.class.getDeclaredField("properties");
            field.setAccessible(true);
            Map properties = (Map) field.get(this);
            properties.put(XMLInputFactory.IS_NAMESPACE_AWARE, true);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
