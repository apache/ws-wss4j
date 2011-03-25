/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package org.swssf.test;

import org.swssf.config.Init;
import org.swssf.ext.WSSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.File;
import java.net.URL;

/**
 *
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class UncategorizedTest {

    @Test
    public void testConfigurationLoadFromUrl() throws Exception {
        URL url = this.getClass().getClassLoader().getResource("testdata/plain-soap.xml");
        try {
            Init.init(url);
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "javax.xml.bind.UnmarshalException\n" +
                    " - with linked exception:\n" +
                    "[org.xml.sax.SAXParseException: cvc-elt.1: Cannot find the declaration of element 'env:Envelope'.]");
        }
    }
}
