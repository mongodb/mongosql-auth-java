/*
 * Copyright 2008-present MongoDB, Inc.
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
 */

package org.mongodb.mongosql.auth.plugin;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import static org.mongodb.mongosql.auth.plugin.BufferHelper.UTF_8;
import static org.mongodb.mongosql.auth.plugin.BufferHelper.writeBytes;
import static java.lang.String.format;

/**
 * An authentication plugin supporting the MongoDB SCRAM-SHA SASL authentication mechanism.
 */
final class ScramSha {

    interface RandomStringGenerator {
        String generate(int length);
    }

    public interface AuthenticationHashGenerator {
        String generate(final String user, final String password) throws SaslException, IllegalArgumentException;
    }

    static SaslClient createSaslClient(final String user, final String password, final String mechanism) {
        return createSaslClient(user, password, mechanism, new DefaultRandomStringGenerator(), getAuthenticationHashGenerator(mechanism));
    }

    static SaslClient createSaslClient(final String user, final String password, final String mechanism,
                                       final RandomStringGenerator randomStringGenerator) {
        return createSaslClient(user, password, mechanism, randomStringGenerator, getAuthenticationHashGenerator(mechanism));
    }

    static SaslClient createSaslClient(final String user, final String password, final String mechanism,
                                       final RandomStringGenerator randomStringGenerator,
                                       final AuthenticationHashGenerator authenticationHashGenerator) {
        return new ScramShaSaslClient(user, password, mechanism, randomStringGenerator,
                                      authenticationHashGenerator);
    }

    private static class ScramShaSaslClient implements SaslClient {
        private static final String GS2_HEADER = "n,,";
        private static final int RANDOM_LENGTH = 24;
        private static final int MINIMUM_ITERATION_COUNT = 4096;
        private static final String SHA_1 = "SCRAM-SHA-1";
        private static final String SHA_256 = "SCRAM-SHA-256";
        private static final byte[] INT_1 = new byte[]{0, 0, 0, 1};

        private final Base64Codec base64Codec;
        private final String user;
        private final String password;
        private final RandomStringGenerator randomStringGenerator;
        private final AuthenticationHashGenerator authenticationHashGenerator;

        private final String hmacAlgorithm;
        private final String hAlgorithm;
        private final String mechanism;
        private String clientFirstMessageBare;
        private String rPrefix;
        private byte[] serverSignature;
        private int step;

        ScramShaSaslClient(final String user, final String password, final String mechanism,
                           final RandomStringGenerator randomStringGenerator,
                           final AuthenticationHashGenerator authenticationHashGenerator
                           ) {
            this.user = user;
            this.password = password;
            this.mechanism = mechanism;
            this.randomStringGenerator = randomStringGenerator;
            this.authenticationHashGenerator = authenticationHashGenerator;

            base64Codec = new Base64Codec();
            if (mechanism.equals(SHA_1)) {
                hmacAlgorithm = "HmacSHA1";
                hAlgorithm = "SHA-1";
            } else {
                hmacAlgorithm = "HmacSHA256";
                hAlgorithm = "SHA-256";
            }
        }

        public String getMechanismName() {
            return hmacAlgorithm;
        }

        public boolean hasInitialResponse() {
            return true;
        }

        public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
            this.step++;

            if (this.step == 1) {
                return computeClientFirstMessage();
            } else if (this.step == 2) {
                return computeClientFinalMessage(challenge);
            } else if (this.step == 3) {
                String serverResponse = encodeUTF8(challenge);
                HashMap<String, String> map = parseServerResponse(serverResponse);

                if (!MessageDigest.isEqual(decodeBase64(map.get("v")), this.serverSignature)) {
                    throw new SaslException("Server signature was invalid.");
                }

                return new byte[0];
            } else {
                throw new SaslException(format("Too many steps involved in the %s negotiation.", this.mechanism));
            }
        }

        public boolean isComplete() {
            return this.step >= 3;
        }

        public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
            throw new UnsupportedOperationException("Not implemented");
        }

        public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
            throw new UnsupportedOperationException("Not implemented ");
        }

        public Object getNegotiatedProperty(final String propName) {
            throw new UnsupportedOperationException("Not implemented");
        }

        public void dispose() throws SaslException {
            // nothing to do
        }

        private byte[] computeClientFirstMessage() throws SaslException {
            String userName = "n=" + prepUserName(user);
            this.rPrefix = randomStringGenerator.generate(RANDOM_LENGTH);

            String nonce = "r=" + this.rPrefix;

            this.clientFirstMessageBare = userName + "," + nonce;
            String clientFirstMessage = GS2_HEADER + this.clientFirstMessageBare;
            return decodeUTF8(clientFirstMessage);
        }

        private byte[] computeClientFinalMessage(final byte[] challenge) throws SaslException {
            String serverFirstMessage = encodeUTF8(challenge);

            HashMap<String, String> map = parseServerResponse(serverFirstMessage);
            String serverNonce = map.get("r");
            if (!serverNonce.startsWith(this.rPrefix)) {
                throw new SaslException("Server sent an invalid nonce.");
            }

            String salt = map.get("s");
            int iterationCount = Integer.parseInt(map.get("i"));
            if (iterationCount < MINIMUM_ITERATION_COUNT) {
                throw new SaslException("Invalid iteration count.");
            }

            String channelBinding = "c=" + encodeBase64(GS2_HEADER);
            String nonce = "r=" + serverNonce;
            String clientFinalMessageWithoutProof = channelBinding + "," + nonce;
            String authMessage = this.clientFirstMessageBare + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof;

            String password = authenticationHashGenerator.generate(this.user, this.password);
            if (this.mechanism.equals(SHA_256)) {
                password = SaslPrep.saslPrepStored(password);
            }

            byte[] saltedPassword = hi(decodeUTF8(password), decodeBase64(salt), iterationCount);

            byte[] clientKey = hmac(saltedPassword, "Client Key");
            byte[] storedKey = h(clientKey);
            byte[] clientSignature = hmac(storedKey, authMessage);
            byte[] clientProof = xor(clientKey, clientSignature);
            byte[] serverKey = hmac(saltedPassword, "Server Key");
            this.serverSignature = hmac(serverKey, authMessage);

            String proof = "p=" + encodeBase64(clientProof);
            String clientFinalMessage = clientFinalMessageWithoutProof + "," + proof;

            return decodeUTF8(clientFinalMessage);
        }

        private byte[] decodeBase64(final String str) {
            return this.base64Codec.decode(str);
        }

        private byte[] decodeUTF8(final String str) throws SaslException {
            try {
                return str.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new SaslException("UTF-8 is not a supported encoding.", e);
            }
        }

        private String encodeBase64(final String str) throws SaslException {
            return this.base64Codec.encode(decodeUTF8(str));
        }

        private String encodeBase64(final byte[] bytes) {
            return this.base64Codec.encode(bytes);
        }

        private String encodeUTF8(final byte[] bytes) throws SaslException {
            try {
                return new String(bytes, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new SaslException("UTF-8 is not a supported encoding.", e);
            }
        }

        private byte[] h(final byte[] data) throws SaslException {
            try {
                return MessageDigest.getInstance(this.hAlgorithm).digest(data);
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException(format("%s could not be found.", hAlgorithm), e);
            }
        }

        private byte[] hi(final byte[] password, final byte[] salt, final int iterations) throws SaslException {
            try {
                SecretKeySpec key = new SecretKeySpec(password, hmacAlgorithm);
                Mac mac = Mac.getInstance(hmacAlgorithm);
                mac.init(key);
                mac.update(salt);
                mac.update(INT_1);
                byte[] result = mac.doFinal();
                byte[] previous = null;
                for (int i = 1; i < iterations; i++) {
                    mac.update(previous != null ? previous : result);
                    previous = mac.doFinal();
                    xorInPlace(result, previous);
                }
                return result;
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException(format("Algorithm for '%s' could not be found.", hmacAlgorithm), e);
            } catch (InvalidKeyException e) {
                throw new SaslException(format("Invalid key for %s", hmacAlgorithm), e);
            }
        }

        private byte[] hmac(final byte[] bytes, final String key) throws SaslException {
            SecretKeySpec signingKey = new SecretKeySpec(bytes, this.hmacAlgorithm);

            Mac mac;
            try {
                mac = Mac.getInstance(this.hmacAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException(format("Could not find %s.", this.hmacAlgorithm), e);
            }

            try {
                mac.init(signingKey);
            } catch (InvalidKeyException e) {
                throw new SaslException("Could not initialize mac.", e);
            }

            return mac.doFinal(decodeUTF8(key));
        }

        /**
         * The server provides back key value pairs using an = sign and delimited
         * by a command. All keys are also a single character.
         * For example: a=kg4io3,b=skljsfoiew,c=1203
         */
        private HashMap<String, String> parseServerResponse(final String response) {
            HashMap<String, String> map = new HashMap<String, String>();
            String[] pairs = response.split(",");
            for (String pair : pairs) {
                String[] parts = pair.split("=", 2);
                map.put(parts[0], parts[1]);
            }

            return map;
        }

        private String prepUserName(final String userName) {
            String user = userName.replace("=", "=3D").replace(",", "=2C");
            return user;
        }

        private byte[] xorInPlace(final byte[] a, final byte[] b) {
            for (int i = 0; i < a.length; i++) {
                a[i] ^= b[i];
            }
            return a;
        }

        private byte[] xor(final byte[] a, final byte[] b) {
            byte[] result = new byte[a.length];

            for (int i = 0; i < a.length; i++) {
                result[i] = (byte) (a[i] ^ b[i]);
            }

            return result;
        }
    }

    private static class DefaultRandomStringGenerator implements RandomStringGenerator {
        public String generate(final int length) {
            int comma = 44;
            int low = 33;
            int high = 126;
            int range = high - low;

            Random random = new SecureRandom();
            char[] text = new char[length];
            for (int i = 0; i < length; i++) {
                int next = random.nextInt(range) + low;
                while (next == comma) {
                    next = random.nextInt(range) + low;
                }
                text[i] = (char) next;
            }
            return new String(text);
        }
    }

    private static final AuthenticationHashGenerator DEFAULT_AUTHENTICATION_HASH_GENERATOR =  new AuthenticationHashGenerator() {
        @Override
        public String generate(final String user, final String password) throws SaslException, IllegalArgumentException {
            if (password == null) {
                throw new IllegalArgumentException("Password must not be null");
            }
            return password;
        }
    };

    private static final AuthenticationHashGenerator LEGACY_AUTHENTICATION_HASH_GENERATOR =  new AuthenticationHashGenerator() {
        @Override
        public String generate(final String user, final String password) throws SaslException, IllegalArgumentException {
            // Username and password must not be modified going into the hash.
            if (user == null || password == null) {
                throw new IllegalArgumentException("Username and password must not be null");
            }
            return ScramSha.createAuthenticationHash(user, password);
        }
    };

    private static AuthenticationHashGenerator getAuthenticationHashGenerator(final String authenticationMechanism) {
        return authenticationMechanism.equals("SCRAM-SHA-1") ? LEGACY_AUTHENTICATION_HASH_GENERATOR : DEFAULT_AUTHENTICATION_HASH_GENERATOR;
    }

    private static String createAuthenticationHash(final String user, final String password) throws SaslException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(user.length() + 20 + password.length());
        writeBytes(baos, user.getBytes(UTF_8));
        writeBytes(baos, ":mongo:".getBytes(UTF_8));
        writeBytes(baos, password.getBytes(UTF_8));

        return hexMD5(baos.toByteArray());
    }

    private static String hexMD5(final byte[] data) throws SaslException {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");

            md5.reset();
            md5.update(data);
            byte[] digest = md5.digest();

            return toHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("MD5 is an unsupported digest type", e);
        }
    }

    private static String toHex(final byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (final byte b : bytes) {
            String s = Integer.toHexString(0xff & b);

            if (s.length() < 2) {
                sb.append("0");
            }
            sb.append(s);
        }
        return sb.toString();
    }

    private ScramSha() {}
}
