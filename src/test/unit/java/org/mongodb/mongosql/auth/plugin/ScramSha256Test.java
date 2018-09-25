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

// import java.util.Arrays;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ScramSha256Test {

    @Test
    public void shouldAuthenticate() throws SaslException {
        // given
        String user = "user";
        String password = "pencil";
        String mechanism = "SCRAM-SHA-256";
        RandomStringGenerator randomStringGenerator = new RandomStringGenerator() {
            @Override
            public String generate(final int length) {
                return "rOprNGfwEbeRWgbNEkqO";
            }
        };

        SaslClient saslClient = ScramSha.createSaslClient(user, password, mechanism, randomStringGenerator);

        // then
        assertFalse(saslClient.isComplete());

        // when
        byte[] response = saslClient.evaluateChallenge(new byte[0]);

        // then
        assertFalse(saslClient.isComplete());
        String expectedResponseHex = "biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=";
        assertArrayEquals(parseBase64Binary(expectedResponseHex), response);

        // when
        String challengeHex = "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZ"
            + "JbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=";
        response = saslClient.evaluateChallenge(parseBase64Binary(challengeHex));
        
        // then
        assertFalse(saslClient.isComplete());
        expectedResponseHex = "Yz1iaXdzLHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyU"
            + "mFUQ0FmdXhGSWxqKWhObEYkazAscD1kSHpiWmFwV0lrNGpVaE4rVXRlOXl0YWc5empmTU"
            + "hnc3FtbWl6N0FuZFZRPQ==";
        assertArrayEquals(parseBase64Binary(expectedResponseHex), response);

        // when
        challengeHex = "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ==";
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
