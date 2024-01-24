package dzt.smartcps.certificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class IPKCert {

    private final CardSchemes certCardScheme;
    private final String certificateFilePath;
    private final byte[] certificateData;
    private String errorMessage;
    CardSchemeBase card;
    public IPKCert(CardSchemes cardScheme, String certificateFilePath) {

        CardSchemes.valueOf(cardScheme.name());
        switch (cardScheme) {
            case VISA:
                card = new VisaCardScheme();
                break;
            case MASTERCARD:
                card = new MasterCardCardScheme();
                break;
            case UPI:
                card = new UpiCardScheme();
                break;
            default:
                throw new IllegalArgumentException("Invalid card scheme");
        }

        this.certCardScheme = cardScheme;
        this.certificateFilePath = certificateFilePath;
        this.certificateData = readCertificate();
        this.errorMessage = null;
    }


    private byte[] readCertificate() {
        try {
            Path path = Paths.get(certificateFilePath);
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new IllegalArgumentException("Error reading certificate file: " + e.getMessage(), e);
        }
    }

    public void displayInfo() {
        System.out.println("Card Scheme: " + certCardScheme.name());
        System.out.println("Certificate File Path: " + certificateFilePath);
        System.out.println("Certificate Data: " + bytesToHex(certificateData));
    }

    public String getCaPublicKeyIndex() {
        return card.getCaPublicKeyIndex(certificateData).toUpperCase();
    }

    public boolean validate(String caPkModulusN, String caPkExponentE) {
        try {
            System.out.println("Recovered using CA Public Key: " + caPkModulusN);
            boolean result = card.recoverIpkCert(caPkModulusN, caPkExponentE, certificateData);
            if (!result) {
                errorMessage = card.getErrorMessage();
            }
            return result;

        } catch (Exception e) {
            return false;
        }
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}

