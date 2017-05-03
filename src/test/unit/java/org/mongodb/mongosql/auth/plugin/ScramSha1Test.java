/*
 * Copyright 2017 MongoDB, Inc.
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
import org.mongodb.mongosql.auth.plugin.ScramSha1.RandomStringGenerator;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ScramSha1Test {

    @Test
    public void shouldAuthenticate() throws SaslException {
        // given
        String user = "user";
        String password = "pencil";
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "fyko+d2lbbFgONRv9qkxdawL";
            }
        };

        SaslClient saslClient = ScramSha1.createSaslClient(user, password, randomStringGenerator);

        // then
        assertFalse(saslClient.isComplete());

        // when
        byte[] response = saslClient.evaluateChallenge(new byte[0]);

        // then
        assertFalse(saslClient.isComplete());
        String expectedResponseHex = "biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM";
        assertArrayEquals(parseBase64Binary(expectedResponseHex), response);

        //when
        String challengeHex = "cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0xIbytWZ2s3cXZVT0tVd3V"
                                      + "XTElXZzRsLzlTcmFHTUhFRSxzPXJROVpZM01udEJldVAzRTFURFZDNHc9PSxpPTEwMDAw";
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex));

        // then
        assertFalse(saslClient.isComplete());
        expectedResponseHex = "Yz1iaXdzLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdMSG8rVmdrN3F"
                                      + "2VU9LVXd1V0xJV2c0bC85U3JhR01IRUUscD1NQzJUOEJ2Ym1XUmNrRHc4b1dsNUlWZ2h3Q1k9";
        assertArrayEquals(parseBase64Binary(expectedResponseHex), response);

        // when
        challengeHex = "dj1VTVdlSTI1SkQxeU5ZWlJNcFo0Vkh2aFo5ZTA9";
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex));

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
