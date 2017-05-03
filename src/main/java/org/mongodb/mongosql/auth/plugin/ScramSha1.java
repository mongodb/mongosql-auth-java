/*
 * Copyright 2008-2017 MongoDB, Inc.
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
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Random;

import static org.mongodb.mongosql.auth.plugin.BufferHelper.UTF_8;
import static org.mongodb.mongosql.auth.plugin.BufferHelper.writeBytes;

/**
 * An authentication plugin supporting the MongoDB SCRAM-SHA-1 SASL authentication mechanism.
 */
final class ScramSha1 {

    interface RandomStringGenerator {
        String generate(int length);
    }

    static SaslClient createSaslClient(final String user, final String password) {
        return createSaslClient(user, password, new DefaultRandomStringGenerator());
    }

    static SaslClient createSaslClient(final String user, final String password, final RandomStringGenerator randomStringGenerator) {
        return new ScramSha1SaslClient(user, randomStringGenerator, password);
    }

    private static class ScramSha1SaslClient implements SaslClient {
        private static final String GS2_HEADER = "n,,";
        private static final int RANDOM_LENGTH = 24;

        private final Base64Codec base64Codec;
        private final String user;
        private final RandomStringGenerator randomStringGenerator;
        private final String password;
        private String clientFirstMessageBare;
        private String rPrefix;
        private byte[] serverSignature;
        private int step;

        ScramSha1SaslClient(final String user, final RandomStringGenerator randomStringGenerator, final String password) {
            this.user = user;
            this.randomStringGenerator = randomStringGenerator;
            this.password = password;
            base64Codec = new Base64Codec();
        }

        public String getMechanismName() {
            return "SCRAM-SHA-1";
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
                throw new SaslException("Too many steps involved in the SCRAM-SHA-1 negotiation.");
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
            String r = map.get("r");
            if (!r.startsWith(this.rPrefix)) {
                throw new SaslException("Server sent an invalid nonce.");
            }

            String s = map.get("s");
            String i = map.get("i");

            String channelBinding = "c=" + encodeBase64(decodeUTF8(GS2_HEADER));
            String nonce = "r=" + r;
            String clientFinalMessageWithoutProof = channelBinding + "," + nonce;

            byte[] saltedPassword = hi(createAuthenticationHash(user, password), decodeBase64(s), Integer.parseInt(i));

            byte[] clientKey = hmac(saltedPassword, "Client Key");
            byte[] storedKey = h(clientKey);
            String authMessage = this.clientFirstMessageBare + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof;
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
                return MessageDigest.getInstance("SHA-1").digest(data);
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException("SHA-1 could not be found.", e);
            }
        }

        private byte[] hi(final String password, final byte[] salt, final int iterations) throws SaslException {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 20 * 8 /* 20 bytes */);

            SecretKeyFactory keyFactory;
            try {
                keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException("Unable to find PBKDF2WithHmacSHA1.", e);
            }

            try {
                return keyFactory.generateSecret(spec).getEncoded();
            } catch (InvalidKeySpecException e) {
                throw new SaslException("Invalid key spec for PBKDC2WithHmacSHA1.", e);
            }
        }

        private byte[] hmac(final byte[] bytes, final String key) throws SaslException {
            SecretKeySpec signingKey = new SecretKeySpec(bytes, "HmacSHA1");

            Mac mac;
            try {
                mac = Mac.getInstance("HmacSHA1");
            } catch (NoSuchAlgorithmException e) {
                throw new SaslException("Could not find HmacSHA1.", e);
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
            return userName.replace("=", "=3D").replace(",", "=2D");
        }

        private byte[] xor(final byte[] a, final byte[] b) {
            byte[] result = new byte[a.length];

            for (int i = 0; i < a.length; i++) {
                result[i] = (byte) (a[i] ^ b[i]);
            }

            return result;
        }

        private String createAuthenticationHash(final String user, final String password) throws SaslException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(user.length() + 20 + password.length());
            writeBytes(baos, user.getBytes(UTF_8));
            writeBytes(baos, ":mongo:".getBytes(UTF_8));
            writeBytes(baos, password.getBytes(UTF_8));

            return hexMD5(baos.toByteArray());
        }

        private String hexMD5(final byte[] data) throws SaslException {
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

        private String toHex(final byte[] bytes) {
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

    private ScramSha1() {}
}
