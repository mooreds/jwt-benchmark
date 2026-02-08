package com.benchmark;

import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;

import java.io.*;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.util.*;

public class SimpleBenchmark {

    private static final int WARMUP = 100;
    private static final int ITERATIONS = 1000;

    public static void main(String[] args) throws Exception {
        System.out.println("======================================================================");
        System.out.println("JWT Signing Algorithm Benchmark");
        System.out.println("======================================================================");
        System.out.println();
        System.out.println("Test payload:");
        System.out.println("  {");
        System.out.println("    \"exp\": 1485140984,");
        System.out.println("    \"iat\": 1485137384,");
        System.out.println("    \"iss\": \"acme.com\",");
        System.out.println("    \"sub\": \"29ac0c18-0b4a-42cf-82fc-03d570318a1d\",");
        System.out.println("    \"applicationId\": \"79103734-97ab-4d1a-af37-e006d05d2952\",");
        System.out.println("    \"roles\": []");
        System.out.println("  }");
        System.out.println();
        System.out.println("Parameters:");
        System.out.println("  Warmup iterations: " + WARMUP);
        System.out.println("  Measured iterations: " + ITERATIONS);
        System.out.println();

        new File("results").mkdirs();

        String signingCsv = "results/signing_benchmarks.csv";
        String verificationCsv = "results/verification_benchmarks.csv";

        try (PrintWriter signWriter = new PrintWriter(new FileWriter(signingCsv));
             PrintWriter verifyWriter = new PrintWriter(new FileWriter(verificationCsv))) {

            signWriter.println("algorithm,key_size,avg_us,min_us,max_us,p95_us,p99_us,token_bytes");
            verifyWriter.println("algorithm,key_size,avg_us,min_us,max_us,p95_us,p99_us");

            JWT jwt = new JWT()
                .setIssuer("acme.com")
                .setSubject("29ac0c18-0b4a-42cf-82fc-03d570318a1d")
                .setIssuedAt(ZonedDateTime.of(2017, 1, 23, 4, 16, 24, 0, ZoneOffset.UTC))
                .setExpiration(ZonedDateTime.of(2017, 1, 23, 4, 22, 24, 0, ZoneOffset.UTC))
                .addClaim("applicationId", "79103734-97ab-4d1a-af37-e006d05d2952")
                .addClaim("roles", new String[]{});

            System.out.println("Running signing benchmarks...");
            System.out.println("----------------------------------------------------------------------");

            for (String algo : KeyGenerator.getAllAlgorithms()) {
                String keySize = KeyGenerator.getKeySizeFromAlgorithm(algo);
                Signer signer = KeyGenerator.getSigner(algo);

                BenchmarkResult result = benchmarkSigning(jwt, signer);

                String token = JWT.getEncoder().encode(jwt, signer);
                int tokenBytes = token.getBytes().length;

                signWriter.printf("%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%d%n",
                    algo, keySize,
                    result.avg, result.min, result.max, result.p95, result.p99, tokenBytes);

                System.out.printf("  %-15s %-8s avg: %8.2f us  min: %8.2f us  max: %9.2f us  p95: %8.2f us  token: %d bytes%n",
                    algo, keySize, result.avg, result.min, result.max, result.p95, tokenBytes);
            }

            System.out.println();
            System.out.println("Running verification benchmarks...");
            System.out.println("----------------------------------------------------------------------");

            Map<String, String> tokens = new HashMap<>();
            for (String algo : KeyGenerator.getAllAlgorithms()) {
                Signer signer = KeyGenerator.getSigner(algo);
                String token = JWT.getEncoder().encode(jwt, signer);
                tokens.put(algo, token);
            }

            for (String algo : KeyGenerator.getAllAlgorithms()) {
                String keySize = KeyGenerator.getKeySizeFromAlgorithm(algo);
                Verifier verifier = KeyGenerator.getVerifier(algo);
                String token = tokens.get(algo);

                BenchmarkResult result = benchmarkVerification(token, verifier);

                verifyWriter.printf("%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f%n",
                    algo, keySize,
                    result.avg, result.min, result.max, result.p95, result.p99);

                System.out.printf("  %-15s %-8s avg: %8.2f us  min: %8.2f us  max: %9.2f us  p95: %8.2f us%n",
                    algo, keySize, result.avg, result.min, result.max, result.p95);
            }

            System.out.println();
            System.out.println("======================================================================");
            System.out.println("Results exported to:");
            System.out.println("  - " + signingCsv);
            System.out.println("  - " + verificationCsv);
            System.out.println("======================================================================");
        }
    }

    private static BenchmarkResult benchmarkSigning(JWT jwt, Signer signer) throws Exception {
        List<Long> times = new ArrayList<>();

        for (int i = 0; i < WARMUP; i++) {
            JWT.getEncoder().encode(jwt, signer);
        }

        System.gc();
        Thread.sleep(100);

        for (int i = 0; i < ITERATIONS; i++) {
            long start = System.nanoTime();
            JWT.getEncoder().encode(jwt, signer);
            long end = System.nanoTime();
            times.add(end - start);
        }

        return calculateStats(times);
    }

    private static BenchmarkResult benchmarkVerification(String token, Verifier verifier) throws Exception {
        List<Long> times = new ArrayList<>();

        java.time.ZonedDateTime validTime = java.time.ZonedDateTime.of(2017, 1, 23, 4, 20, 0, 0, java.time.ZoneOffset.UTC);

        for (int i = 0; i < WARMUP; i++) {
            JWT.getTimeMachineDecoder(validTime).decode(token, verifier);
        }

        System.gc();
        Thread.sleep(100);

        for (int i = 0; i < ITERATIONS; i++) {
            long start = System.nanoTime();
            JWT.getTimeMachineDecoder(validTime).decode(token, verifier);
            long end = System.nanoTime();
            times.add(end - start);
        }

        return calculateStats(times);
    }

    private static BenchmarkResult calculateStats(List<Long> times) {
        Collections.sort(times);

        double avg = times.stream().mapToLong(Long::longValue).average().orElse(0);
        double min = times.get(0);
        double max = times.get(times.size() - 1);

        int p95Index = (int) (times.size() * 0.95);
        int p99Index = (int) (times.size() * 0.99);

        double p95 = times.get(p95Index);
        double p99 = times.get(p99Index);

        return new BenchmarkResult(avg / 1000.0, min / 1000.0, max / 1000.0, p95 / 1000.0, p99 / 1000.0);
    }

    static class BenchmarkResult {
        final double avg, min, max, p95, p99;

        BenchmarkResult(double avg, double min, double max, double p95, double p99) {
            this.avg = avg;
            this.min = min;
            this.max = max;
            this.p95 = p95;
            this.p99 = p99;
        }
    }
}
