/*
 * Copyright 2018 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.mongodb.mongosql.auth.plugin;

import org.junit.Test;
import org.mongodb.mongosql.auth.plugin.ScramSha.RandomStringGenerator;
import org.mongodb.mongosql.auth.plugin.ScramSha.AuthenticationHashGenerator;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ScramSha256Test {
    private String mechanism = "SCRAM-SHA-256";
    private String user = "user";
    private String password;
    private String expectedResponseHex1;
    private String expectedResponseHex2;
    private String challengeHex1;
    private String challengeHex2;
    private Base64Codec base64codec = new Base64Codec();

    @Test
    public void shouldAuthenticateASCII() throws SaslException {
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "clientNONCE";
            }
        };
        this.user = "user";
        this.password = "pencil";

        // C: n,,n=user,r=clientNONCE
        expectedResponseHex1 = "biwsbj11c2VyLHI9Y2xpZW50Tk9OQ0U=";

        // S: r=clientNONCEserverNONCE,s=c2FsdFNBTFRzYWx0,i=4096
        challengeHex1 = "cj1jbGllbnROT05DRXNlcnZlck5PTkNFLHM9YzJGc2RGTkJURlJ6WVd4MCxpPTQwOTY=";

        // C: c=biws,r=clientNONCEserverNONCE,p=ItXnHvCDW7VGij6H+4rv2o93HvkLwrQaLkfVjeSMfrc=
        expectedResponseHex2 = "Yz1iaXdzLHI9Y2xpZW50Tk9OQ0VzZXJ2ZXJOT05DRSxwPUl0WG5I"
            + "dkNEVzdWR2lqNkgrNHJ2Mm85M0h2a0x3clFhTGtmVmplU01mcmM9";

        // S: v=P61v8wxOu6B9J7Uij+Sk4zewSK1e6en6f5rCFO4OUNE=
        challengeHex2 = "dj1QNjF2OHd4T3U2QjlKN1VpaitTazR6ZXdTSzFlNmVuNmY1ckNGTzRPVU5FPQ==";
        runTest(randomStringGenerator);
    }

    @Test
    public void shouldAuthenticateFromRFCSpec() throws SaslException {
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "rOprNGfwEbeRWgbNEkqO";
            }
        };
        this.user = "user";
        this.password = "pencil";

        // C: n,,n=user,r=rOprNGfwEbeRWgbNEkqO
        expectedResponseHex1 = "biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=";

        // S: r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096
        challengeHex1 = "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZ"
            + "JbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=";

        // C: c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
        expectedResponseHex2 = "Yz1iaXdzLHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyU"
            + "mFUQ0FmdXhGSWxqKWhObEYkazAscD1kSHpiWmFwV0lrNGpVaE4rVXRlOXl0YWc5empmTU"
            + "hnc3FtbWl6N0FuZFZRPQ==";

        // S: v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=
        challengeHex2 = "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ==";
        runTest(randomStringGenerator);
    }

    @Test
    public void shouldAuthenticateASCIIUser() throws SaslException {
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "clientNONCE";
            }
        };
        this.user = "user";
        this.password = "p\u00e8ncil";

        // C: n,,n=user,r=clientNONCE
        expectedResponseHex1 = "biwsbj11c2VyLHI9Y2xpZW50Tk9OQ0U=";

        // S: r=clientNONCEserverNONCE,s=c2FsdFNBTFRzYWx0,i=4096
        challengeHex1 = "cj1jbGllbnROT05DRXNlcnZlck5PTkNFLHM9YzJGc2RGTkJURlJ6WVd4MCxpPTQwOTY=";

        // C: c=biws,r=clientNONCEserverNONCE,p=o6rKPfQCKSGHClFxHjdSeiVCPA6K53++gpY3XlP8lI8=
        expectedResponseHex2 = "Yz1iaXdzLHI9Y2xpZW50Tk9OQ0VzZXJ2ZXJOT05DRSxwPW82"
            + "cktQZlFDS1NHSENsRnhIamRTZWlWQ1BBNks1MysrZ3BZM1hsUDhsSTg9";

        // S: v=rsyNAwnHfclZKxAKx1tKfInH3xPVAzCy237DQo5n/N8=
        challengeHex2 = "dj1yc3lOQXduSGZjbFpLeEFLeDF0S2ZJbkgzeFBWQXpDeTIzN0RRbzVuL044PQ==";
        runTest(randomStringGenerator);
    }

    @Test
    public void shouldAuthenticateASCIIPass() throws SaslException {
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "clientNONCE";
            }
        };
        this.user = "ram\u00f5n";
        this.password = "pencil";

        // C: n,,n=ramõn,r=clientNONCE
        expectedResponseHex1 = "biwsbj1yYW3DtW4scj1jbGllbnROT05DRQ==";

        // S: r=clientNONCEserverNONCE,s=c2FsdFNBTFRzYWx0,i=4096
        challengeHex1 = "cj1jbGllbnROT05DRXNlcnZlck5PTkNFLHM9YzJGc2RGTkJURlJ6WVd4MCxpPTQwOTY=";

        // C: c=biws,r=clientNONCEserverNONCE,p=vRdD7SqiY5kMyAFX2enPOJK9BL+3YIVyuzCt1H2qc4o=
        expectedResponseHex2 = "Yz1iaXdzLHI9Y2xpZW50Tk9OQ0VzZXJ2ZXJOT05DRSxwPXZSZEQ"
            + "3U3FpWTVrTXlBRlgyZW5QT0pLOUJMKzNZSVZ5dXpDdDFIMnFjNG89";

        // S: v=sh7QPwVuquMatYobYpYOaPiNS+lqwTCmy3rdexRDDkE=
        challengeHex2 = "dj1zaDdRUHdWdXF1TWF0WW9iWXBZT2FQaU5TK2xxd1RDbXkzcmRleFJERGtFPQ==";
        runTest(randomStringGenerator);
    }

    @Test
    public void shouldAuthenticateSASLNormal() throws SaslException {
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "clientNONCE";
            }
        };
        this.user = "ram\u00f5n";
        this.password = "p\u00c5assword";

        // C: n,,n=ramõn,r=clientNONCE
        expectedResponseHex1 = "biwsbj1yYW3DtW4scj1jbGllbnROT05DRQ==";

        // S: r=clientNONCEserverNONCE,s=c2FsdFNBTFRzYWx0,i=4096
        challengeHex1 = "cj1jbGllbnROT05DRXNlcnZlck5PTkNFLHM9YzJGc2RGTkJURlJ6WVd4MCxpPTQwOTY=";

        // C: c=biws,r=clientNONCEserverNONCE,p=Km2zqmf/GbLdkItzscNI5D0c1f+GmLDi2fScTPm6d4k=
        expectedResponseHex2 = "Yz1iaXdzLHI9Y2xpZW50Tk9OQ0VzZXJ2ZXJOT05DRSxwPUttMnpxbWYvR2JMZGtJdHpzY05JNUQwYzFmK0dtTERpMmZTY1RQbTZkNGs9";

        // S: v=30soY0l2BiInoDyrHxIuamz2LBvci1lFKo/tOMpqo98=
        challengeHex2 = "dj0zMHNvWTBsMkJpSW5vRHlySHhJdWFtejJMQnZjaTFsRktvL3RPTXBxbzk4PQ==";
        runTest(randomStringGenerator);
    }

    @Test
    public void shouldAuthenticateSASLNonNormal() throws SaslException {
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "clientNONCE";
            }
        };
        AuthenticationHashGenerator authenticationHashGenerator = new AuthenticationHashGenerator() {
            @Override
            public String generate(final String user, final String password) {
                return "p\u00c5ssword";
            }
        };
        this.user = "ramo\u0301n";
        this.password = "p\u212bssword";

        // C: n,,n=ramón,r=clientNONCE
        expectedResponseHex1 = "biwsbj1yYW1vzIFuLHI9Y2xpZW50Tk9OQ0U=";

        // S: r=clientNONCEserverNONCE,s=c2FsdFNBTFRzYWx0,i=4096
        challengeHex1 = "cj1jbGllbnROT05DRXNlcnZlck5PTkNFLHM9YzJGc2RGTkJURlJ6WVd4MCxpPTQwOTY=";

        // C: c=biws,r=clientNONCEserverNONCE,p=KkLV/eEHHw0LrTlnmElWuTiL0RxDa8lF/RqzsDP04sE=
        expectedResponseHex2 = "Yz1iaXdzLHI9Y2xpZW50Tk9OQ0VzZXJ2ZXJOT05DRSxwPUtrTFY"
            + "vZUVISHcwTHJUbG5tRWxXdVRpTDBSeERhOGxGL1JxenNEUDA0c0U9";

        // S: v=eLTDerRxJFOBV8+/9xOcIkv4PezVAcNAarSyqa5mQyI=
        challengeHex2 = "dj1lTFREZXJSeEpGT0JWOCsvOXhPY0lrdjRQZXpWQWNOQWFyU3lxYTVtUXlJPQ==";
        runTest(randomStringGenerator, authenticationHashGenerator);
    }

    @Test(expected = SaslException.class)
    public void shouldNotAuthenticateSASLException() throws SaslException {
        this.user = "user";
        this.password = "pencil";

        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "rOprNGfwEbeRWgbNEkqO";
            }
        };
        SaslClient saslClient = ScramSha.createSaslClient(user, password, mechanism,
                                                          randomStringGenerator);

        byte[] response = saslClient.evaluateChallenge(new byte[0]);

        // when
        challengeHex1 = "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZ"
            + "JbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=";
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex1));

        // when
        challengeHex2 = "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ==";
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex2));

        // should generate exception
        String challengeHex3 = "ej1FeHRyYVN0ZXA=";
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex3));
    }

    private void runTest(final RandomStringGenerator randomStringGenerator) throws SaslException {
        runTest(randomStringGenerator, null);
    }

    private void runTest(final RandomStringGenerator randomStringGenerator,
                         final AuthenticationHashGenerator authHashGenerator) throws SaslException {
        SaslClient saslClient;

        if (authHashGenerator == null) {
            saslClient = ScramSha.createSaslClient(user, password, mechanism, randomStringGenerator);
        } else {
            saslClient = ScramSha.createSaslClient(user, password, mechanism,
                                                   randomStringGenerator, authHashGenerator);
        }

        // then
        assertFalse(saslClient.isComplete());

        // when
        byte[] response = saslClient.evaluateChallenge(new byte[0]);

        // then
        assertFalse(saslClient.isComplete());
        assertArrayEquals(parseBase64Binary(expectedResponseHex1), response);

        // when
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex1));

        // then
        assertFalse(saslClient.isComplete());
        assertArrayEquals(parseBase64Binary(expectedResponseHex2), response);

        // when
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex2));

        // then
        assertTrue(saslClient.isComplete());
        assertArrayEquals(new byte[0], response);

        // when
        try {
            saslClient.evaluateChallenge(new byte[0]);
            fail();
        } catch (SaslException e) {
            // all good
        }
    }

}
