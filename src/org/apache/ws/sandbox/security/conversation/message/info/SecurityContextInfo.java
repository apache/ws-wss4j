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

package org.apache.ws.security.conversation.message.info;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.token.RequestedProofToken;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Class SecurityContextInfo
 */
public class SecurityContextInfo {

    /**
     * Field sharedSecret
     */
    private byte[] sharedSecret;

    /**
     * Field expiration
     */
    private String expiration;

    /**
     * Field expirationDate
     */
    private Date expirationDate;

    /**
     * Field identifier
     */
    private String identifier;

    /**
     * Field frequency
     */
    private int frequency;

    /**
     * This element will be useful to store in the hashtable to get
     * information about the security context
     * 
     * @param securityContextToken 
     * @param requestedProofToken  
     * @param frequency            
     * @throws WSSecurityException 
     */
    public SecurityContextInfo(SecurityContextToken securityContextToken, RequestedProofToken requestedProofToken, int frequency)
            throws WSSecurityException {
        this.sharedSecret = requestedProofToken.getSharedSecret();

        // call the public method to set both string and the date value
        this.setExpiration(securityContextToken.getExpires());    // wrong : Ruchith--> Need to provide a method to get Expiration
        this.identifier = securityContextToken.getIdentifier();
        this.frequency = frequency;    // frequency of refreshing the derrived key

        // check for nullity throw exceptions
    }

    /**
     * This constructor will be useful to create a SecurityContextInfo object
     * without having SecurityContextToken and RequestedProofToken
     * Specially for testing purposes
     * 
     * @param sharedSecret 
     * @param expiration   
     * @param frequency    
     * @throws WSSecurityException 
     */
    public SecurityContextInfo(byte[] sharedSecret, String expiration, int frequency)
            throws WSSecurityException {
        this.sharedSecret = sharedSecret;

        // call the public method to set both string and the date value
        this.setExpiration(expiration);
        this.frequency = frequency;
    }

    /**
     * @return shared secret
     */
    public byte[] getSharedSecret() {
        return this.sharedSecret;
    }

    /**
     * @return shared secret as a byte array
     */
    public byte[] getSharedSecretAsByteArray() {
        return this.sharedSecret;
    }

    /**
     * @return expiration date
     */
    public String getexpiration() {
        return this.expiration;
    }

    /**
     * Set expiration date
     * 
     * @param created    
     * @param expiration 
     * @throws WSSecurityException 
     */
    public void setExpiration(String expiration) throws WSSecurityException {
        this.expiration = expiration;
        this.expirationDate = this.getDate(expiration);
    }

    /**
     * @return 
     */
    public String getIdentifier() {
        return this.identifier;
    }

    /**
     * @return frequency of refreshing the derrived key
     */
    public int getFrequency() {
        return frequency;
    }

    /**
     * @param frequency : frequency of refreshing the derrived key
     */
    public void setFrequency(int frequency) {
        this.frequency = frequency;
    }

    /**
     * @return 
     * @throws WSSecurityException 
     */
    public boolean isExpired() throws WSSecurityException {
        boolean isExpired;
        Calendar rightNow = Calendar.getInstance();
        SimpleDateFormat zulu =
                new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("GMT"));

        // go through the same process  to current time as the expiration time
        // before the comparison
        Date date = this.getDate(zulu.format(rightNow.getTime()));

        // if the expiration is before current time return to
        isExpired = this.expirationDate.before(date);
        return isExpired;
    }

    /**
     * To get a Date object given a string(Expiration date)
     * E.g. 2001-10-13T09:00:00Z
     * Shall we put these functions in a util packege
     * WSConversation.util will be handy :)
     * 
     * @param strDate 
     * @return 
     * @throws WSSecurityException 
     */
    private Date getDate(String strDate) throws WSSecurityException {
        Date date;
        System.out.println("Date is ::" + strDate);
        try {
            // Date "T" Time
            String[] dateTimeSplits = strDate.split("T");
            String strDatePart = dateTimeSplits[0].trim();
            String strTimePart = dateTimeSplits[1].trim();

            // Date 2001-10-13
            String[] dateSplits = strDatePart.split("-");
            String sYear = dateSplits[0].trim();
            String sMonth = dateSplits[1].trim();
            String sDate = dateSplits[2].trim();

            // Time 09:00:00Z
            String[] timeSplits = strTimePart.split(":");
            String sHr = timeSplits[0].trim();
            String sMin = timeSplits[1].trim();
            String sSec = timeSplits[2].replace('Z', ' ').trim();
            date = new Date(Integer.parseInt(sYear), Integer.parseInt(sMonth),
                    Integer.parseInt(sDate), Integer.parseInt(sHr),
                    Integer.parseInt(sMin), Integer.parseInt(sSec));
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "Can not convert to a date");
        }
        return date;
    }

    /**
     * @param bs 
     */
    public void setSharedSecret(byte[] bs) {
        sharedSecret = bs;
    }
}
