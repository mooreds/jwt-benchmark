package com.benchmark;

import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;
import io.fusionauth.jwt.ec.ECSigner;
import io.fusionauth.jwt.ec.ECVerifier;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.ed.EdDSASigner;
import io.fusionauth.jwt.ed.EdDSAVerifier;

import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class KeyGenerator {
    private static final Map<String, Signer> signers = new ConcurrentHashMap<>();
    private static final Map<String, Verifier> verifiers = new ConcurrentHashMap<>();
    private static final Map<String, KeyPair> keyPairs = new ConcurrentHashMap<>();

    public static final String HMAC_256 = "HS256";
    public static final String HMAC_384 = "HS384";
    public static final String HMAC_512 = "HS512";

    public static final String RSA_2048 = "RSA-2048";
    public static final String RSA_3072 = "RSA-3072";
    public static final String RSA_4096 = "RSA-4096";

    public static final String RSA_PSS_2048 = "PSS-2048";
    public static final String RSA_PSS_3072 = "PSS-3072";
    public static final String RSA_PSS_4096 = "PSS-4096";

    public static final String ECDSA_256 = "EC-P256";
    public static final String ECDSA_384 = "EC-P384";
    public static final String ECDSA_521 = "EC-P521";

    public static final String ED25519 = "Ed25519";

    static {
        generateAllKeys();
    }

    private static void generateAllKeys() {
        try {
            generateHMACKeys();
            generateRSAKeys(2048);
            generateRSAKeys(3072);
            generateRSAKeys(4096);
            generateECKeys(256);
            generateECKeys(384);
            generateECKeys(521);
            generateEdDSAKeys();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate keys", e);
        }
    }

    private static void generateHMACKeys() throws NoSuchAlgorithmException {
        byte[] secret256 = generateHMACSecret(32);
        byte[] secret384 = generateHMACSecret(48);
        byte[] secret512 = generateHMACSecret(64);

        signers.put(HMAC_256, HMACSigner.newSHA256Signer(secret256));
        verifiers.put(HMAC_256, HMACVerifier.newVerifier(secret256));

        signers.put(HMAC_384, HMACSigner.newSHA384Signer(secret384));
        verifiers.put(HMAC_384, HMACVerifier.newVerifier(secret384));

        signers.put(HMAC_512, HMACSigner.newSHA512Signer(secret512));
        verifiers.put(HMAC_512, HMACVerifier.newVerifier(secret512));
    }

    private static byte[] generateHMACSecret(int bytes) {
        byte[] secret = new byte[bytes];
        new SecureRandom().nextBytes(secret);
        return secret;
    }

    private static void generateRSAKeys(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();

        String keyLabel = "RSA-" + keySize;
        String pssKeyLabel = "PSS-" + keySize;

        keyPairs.put(keyLabel, keyPair);
        keyPairs.put(pssKeyLabel, keyPair);

        signers.put("RS256-" + keySize, RSASigner.newSHA256Signer(keyPair.getPrivate()));
        signers.put("RS384-" + keySize, RSASigner.newSHA384Signer(keyPair.getPrivate()));
        signers.put("RS512-" + keySize, RSASigner.newSHA512Signer(keyPair.getPrivate()));

        signers.put("PS256-" + keySize, RSASigner.newSHA256Signer(keyPair.getPrivate()));
        signers.put("PS384-" + keySize, RSASigner.newSHA384Signer(keyPair.getPrivate()));
        signers.put("PS512-" + keySize, RSASigner.newSHA512Signer(keyPair.getPrivate()));

        verifiers.put("RS256-" + keySize, RSAVerifier.newVerifier(keyPair.getPublic()));
        verifiers.put("RS384-" + keySize, RSAVerifier.newVerifier(keyPair.getPublic()));
        verifiers.put("RS512-" + keySize, RSAVerifier.newVerifier(keyPair.getPublic()));

        verifiers.put("PS256-" + keySize, RSAVerifier.newVerifier(keyPair.getPublic()));
        verifiers.put("PS384-" + keySize, RSAVerifier.newVerifier(keyPair.getPublic()));
        verifiers.put("PS512-" + keySize, RSAVerifier.newVerifier(keyPair.getPublic()));
    }

    private static void generateECKeys(int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        String curveName;
        switch (keySize) {
            case 256: curveName = "secp256r1"; break;
            case 384: curveName = "secp384r1"; break;
            case 521: curveName = "secp521r1"; break;
            default: throw new IllegalArgumentException("Unsupported EC key size: " + keySize);
        }

        ECParameterSpec ecSpec = getECParameterSpec(curveName);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        String keyLabel = "EC-P" + keySize;
        keyPairs.put(keyLabel, keyPair);

        String algo = "ES" + (keySize == 521 ? 512 : keySize);
        switch (keySize) {
            case 256:
                signers.put("ES256-256", ECSigner.newSHA256Signer(keyPair.getPrivate()));
                break;
            case 384:
                signers.put("ES384-384", ECSigner.newSHA384Signer(keyPair.getPrivate()));
                break;
            case 521:
                signers.put("ES512-521", ECSigner.newSHA512Signer(keyPair.getPrivate()));
                break;
        }
        verifiers.put(algo + "-" + keySize, ECVerifier.newVerifier(keyPair.getPublic()));
    }

    private static ECParameterSpec getECParameterSpec(String curveName) throws NoSuchAlgorithmException, InvalidParameterSpecException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveName));
        return params.getParameterSpec(ECParameterSpec.class);
    }

    private static void generateEdDSAKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyGen.generateKeyPair();
        keyPairs.put(ED25519, keyPair);

        signers.put(ED25519, EdDSASigner.newSigner(keyPair.getPrivate()));
        verifiers.put(ED25519, EdDSAVerifier.newVerifier(keyPair.getPublic()));
    }

    public static Signer getSigner(String algorithm) {
        return signers.get(algorithm);
    }

    public static Verifier getVerifier(String algorithm) {
        return verifiers.get(algorithm);
    }

    public static List<String> getAllAlgorithms() {
        List<String> algos = new ArrayList<>();

        algos.add(HMAC_256);
        algos.add(HMAC_384);
        algos.add(HMAC_512);

        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("RS256-" + size);
            algos.add("RS384-" + size);
            algos.add("RS512-" + size);
            algos.add("PS256-" + size);
            algos.add("PS384-" + size);
            algos.add("PS512-" + size);
        }

        algos.add("ES256-256");
        algos.add("ES384-384");
        algos.add("ES512-521");

        algos.add(ED25519);

        return algos;
    }

    public static List<String> getHMACAlgorithms() {
        return Arrays.asList(HMAC_256, HMAC_384, HMAC_512);
    }

    public static List<String> getRS256Algorithms() {
        List<String> algos = new ArrayList<>();
        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("RS256-" + size);
        }
        return algos;
    }

    public static List<String> getRS384Algorithms() {
        List<String> algos = new ArrayList<>();
        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("RS384-" + size);
        }
        return algos;
    }

    public static List<String> getRS512Algorithms() {
        List<String> algos = new ArrayList<>();
        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("RS512-" + size);
        }
        return algos;
    }

    public static List<String> getPS256Algorithms() {
        List<String> algos = new ArrayList<>();
        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("PS256-" + size);
        }
        return algos;
    }

    public static List<String> getPS384Algorithms() {
        List<String> algos = new ArrayList<>();
        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("PS384-" + size);
        }
        return algos;
    }

    public static List<String> getPS512Algorithms() {
        List<String> algos = new ArrayList<>();
        for (int size : new int[]{2048, 3072, 4096}) {
            algos.add("PS512-" + size);
        }
        return algos;
    }

    public static List<String> getECDSAAlgorithms() {
        return Arrays.asList("ES256-256", "ES384-384", "ES512-521");
    }

    public static List<String> getEdDSAAlgorithms() {
        return Collections.singletonList(ED25519);
    }

    public static String getKeySizeFromAlgorithm(String algorithm) {
        if (algorithm.startsWith("HS")) {
            switch (algorithm) {
                case "HS256": return "256";
                case "HS384": return "384";
                case "HS512": return "512";
            }
        } else if (algorithm.startsWith("ES")) {
            if (algorithm.contains("256")) return "256";
            if (algorithm.contains("384")) return "384";
            if (algorithm.contains("512")) return "521";
        } else if (algorithm.contains("-")) {
            String[] parts = algorithm.split("-");
            if (parts.length == 2) {
                return parts[1];
            } else if (parts.length == 3) {
                return parts[2];
            }
        } else if (algorithm.equals("Ed25519")) {
            return "25519";
        }
        return "unknown";
    }
}
