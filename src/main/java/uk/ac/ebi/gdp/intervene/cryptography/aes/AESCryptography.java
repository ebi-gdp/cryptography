/*
 *
 * Copyright 2024 EMBL - European Bioinformatics Institute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package uk.ac.ebi.gdp.intervene.cryptography.aes;

import uk.ac.ebi.gdp.intervene.cryptography.aes.exception.CryptographyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * AES symmetric encryption/decryption cryptography utility.
 */
public class AESCryptography {
    private final String algorithm;
    private final String cipherAlgorithm;
    private final int keySize;
    private final int saltSize;
    private final int ivSize;
    private final int tagSize;
    private final int iterationCount;
    private final SecureRandom secureRandom;

    private AESCryptography(final Builder builder) {
        this.algorithm = builder.algorithm;
        this.cipherAlgorithm = builder.cipherAlgorithm;
        this.keySize = builder.keySize;
        this.saltSize = builder.saltSize;
        this.ivSize = builder.ivSize;
        this.tagSize = builder.tagSize;
        this.iterationCount = builder.iterationCount;
        this.secureRandom = new SecureRandom();
    }

    public String encrypt(final byte[] data,
                          final char[] password) {
        try {
            return doEncrypt(data, password);
        } catch (Exception e) {
            throw new CryptographyException("There is an issue with AES encryption: " + e.getMessage(), e);
        }
    }

    private String doEncrypt(final byte[] data,
                             final char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        final byte[] salt = generateSalt();
        final SecretKey secretKey = getKeyFromPassword(password, salt);
        final Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        final byte[] iv = generateIV();
        final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagSize, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        final byte[] encryptedData = cipher.doFinal(data);
        final byte[] encryptedDataWithIvSalt = concatenate(iv, salt, encryptedData);
        return Base64
                .getEncoder()
                .encodeToString(encryptedDataWithIvSalt);
    }

    public byte[] decrypt(final String encryptedData,
                          final char[] password) {
        try {
            return doDecrypt(encryptedData, password);
        } catch (Exception e) {
            throw new CryptographyException("There is an issue with AES decryption: " + e.getMessage(), e);
        }
    }

    private byte[] doDecrypt(final String encryptedData,
                             final char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final byte[] decodedData = Base64
                .getDecoder()
                .decode(encryptedData);
        final byte[] iv = new byte[ivSize];
        final byte[] salt = new byte[saltSize];
        final byte[] actualEncryptedData = new byte[decodedData.length - ivSize - saltSize];

        System.arraycopy(decodedData, 0, iv, 0, ivSize);
        System.arraycopy(decodedData, ivSize, salt, 0, saltSize);
        System.arraycopy(decodedData, ivSize + saltSize, actualEncryptedData, 0, actualEncryptedData.length);

        final SecretKey secretKey = getKeyFromPassword(password, salt);
        final Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagSize, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        return cipher.doFinal(actualEncryptedData);
    }

    private byte[] generateSalt() {
        final byte[] salt = new byte[saltSize];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private byte[] generateIV() {
        final byte[] iv = new byte[ivSize];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private SecretKey getKeyFromPassword(final char[] password,
                                         final byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, keySize);
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, algorithm);
    }

    private byte[] concatenate(final byte[] iv,
                               final byte[] salt,
                               final byte[] data) {
        final byte[] result = new byte[iv.length + salt.length + data.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(salt, 0, result, iv.length, salt.length);
        System.arraycopy(data, 0, result, iv.length + salt.length, data.length);
        return result;
    }

    public static class Builder {
        private String algorithm = "AES";
        private String cipherAlgorithm = "AES/GCM/NoPadding";
        private int keySize = 128;
        private int saltSize = 16;
        private int ivSize = 12;
        private int tagSize = 128;
        private int iterationCount = 65536;

        public Builder withAlgorithm(final String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder withCipherAlgorithm(final String cipherAlgorithm) {
            this.cipherAlgorithm = cipherAlgorithm;
            return this;
        }

        public Builder withKeySize(final int keySize) {
            this.keySize = keySize;
            return this;
        }

        public Builder withSaltSize(final int saltSize) {
            this.saltSize = saltSize;
            return this;
        }

        public Builder withIvSize(final int ivSize) {
            this.ivSize = ivSize;
            return this;
        }

        public Builder withTagSize(final int tagSize) {
            this.tagSize = tagSize;
            return this;
        }

        public Builder withIterationCount(final int iterationCount) {
            this.iterationCount = iterationCount;
            return this;
        }

        public AESCryptography build() {
            return new AESCryptography(this);
        }
    }
}
