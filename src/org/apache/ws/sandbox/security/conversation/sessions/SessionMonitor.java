/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.sandbox.security.conversation.sessions;

/**
 * Monitor for the conversation sessions
 * @author Ruchith Fernando
 * @version 1.0
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.sandbox.security.conversation.ConversationException;
import org.apache.ws.sandbox.security.conversation.ConversationSession;
import org.apache.ws.security.util.Loader;

import java.net.URL;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Vector;

public class SessionMonitor extends Thread {

    private Log log = LogFactory.getLog(SessionMonitor.class.getName());

    /**
     * Session lifetime in milliseconds
     */
    private long sessionLifetime;

    /**
     * 
     */
    private long reapPeriodicity;

    /**
     *
     */
    private Hashtable sessionTable;

    /**
     *
     */
    private Vector expiredSessions = new Vector();

    private long lastReaped = System.currentTimeMillis();

    public SessionMonitor(Hashtable sessionTable)
            throws ConversationException {
        //this.setPriority(Thread.MAX_PRIORITY);
        try {
            Properties prop = getProperties("SessionMonitor.properties");
            this.reapPeriodicity =
                    Long.parseLong(prop.getProperty("org.apache.ws.security.converasation.session.reapPeriodicity"));
            this.sessionLifetime =
                    Long.parseLong(prop.getProperty("org.apache.ws.security.converasation.session.sessionLifetime"));
            log.debug("Reap periodicity from prop file: " + this.reapPeriodicity);
            log.debug("Session lifetime from prop file: " + this.sessionLifetime);
        } catch (Exception e) {
            log.debug("SessionMonitor: Cannot load SessionMonitor.properties using defaults: \n"
                    + "org.apache.ws.security.converasation.session.reapInterval="
                    + 60000
                    + "org.apache.ws.security.converasation.session.sessionLifetime"
                    + 1800000);
            this.reapPeriodicity = 60000;
            this.sessionLifetime = 1800000;
        }
        this.sessionTable = sessionTable;
        log.debug("Session monitor created");
    }

    /**
     * STOLEN FROM  org.apache.ws.security.components.crypto.CryptoFactory
     * Gets the properties for SessionMonitor
     * The functions loads the property file via
     * {@link Loader.getResource(String)}, thus the property file
     * should be accesible via the classpath
     *
     * @param propFilename the properties file to load
     * @return a <code>Properties</code> object loaded from the filename
     */
    private Properties getProperties(String propFilename) {
        Properties properties = new Properties();
        try {
            URL url = Loader.getResource(propFilename);
            properties.load(url.openStream());
            log.debug("SessionMonitor.properties found");
        } catch (Exception e) {
            log.debug("Cannot find SessionMonitor property file: " + propFilename);
            throw new RuntimeException("SessionMonitor: Cannot load properties: " + propFilename);
        }
        return properties;
    }

    public void run() {
        while (true) {
            long now = System.currentTimeMillis();
            log.debug("Diff: " + (now - (lastReaped + reapPeriodicity)));
            if (now > (lastReaped + reapPeriodicity)) {
                log.debug("Special:Ruchith:Waiting to get session");
                synchronized (this.sessionTable) {
                    log.debug("Checking sessions");
                    Enumeration keys = this.sessionTable.keys();
                    while (keys.hasMoreElements()) {
                        String tempId = (String) keys.nextElement();
                        ConversationSession session =
                                (ConversationSession) this.sessionTable.get(tempId);
                        synchronized (session) {
                            log.debug("Session: " + tempId);
                            if (this.isExpirable(session))
                                this.expireSession(tempId);
                        }
                    }
                }
                lastReaped = now;
            }
            try {
                sleep(reapPeriodicity / 2);
            } catch (InterruptedException e) {
                log.debug(e.getMessage());
            }

        }

    }

    private boolean isExpirable(ConversationSession session) {
        long lastTouched = session.getLastTouched();
        if ((lastTouched + this.sessionLifetime) < System.currentTimeMillis())
            return true;
        else
            return false;
    }

    private void expireSession(String identifier) {
        log.debug("Expirign session " + identifier);
        this.sessionTable.remove(identifier);
        this.expiredSessions.add(identifier);
    }

    public Vector getExpiredSessionIds() {
        return (Vector) this.expiredSessions.clone();
    }

    public Hashtable getLiveSessions() {
        return (Hashtable) this.sessionTable.clone();
    }

}
