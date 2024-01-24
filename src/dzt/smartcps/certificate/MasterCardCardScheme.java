package dzt.smartcps.certificate;

import java.math.BigInteger;
import java.util.Arrays;

public class MasterCardCardScheme extends CardSchemeBase {
	MasterCardUnsignedData unsignedData = new MasterCardUnsignedData();
    MasterCardCertificateData certificateData = new MasterCardCertificateData();


    byte[] readUnsignedData(byte[] ipkCertData, int caPkModulusNLength) {
        try {
            byte[] unsignedDataBuffer;

            int ipkCertDataLength = ipkCertData.length;
            if (ipkCertDataLength < (caPkModulusNLength + 8)) {
                throw new IllegalArgumentException("Invalid Certificate data format!");
            } else {
                unsignedDataBuffer = Arrays.copyOfRange(ipkCertData, 0, ipkCertDataLength - caPkModulusNLength);
            }
            int offset = 0;  // Starting offset
            unsignedData.issuerIdentificationNumber = Arrays.copyOfRange(ipkCertData, offset, offset + 4);
            offset += 4;

            unsignedData.issuerPublicKeyIndex = Arrays.copyOfRange(ipkCertData, offset, offset + 3);
            offset += 3;

            unsignedData.caPublicKeyIndex = Arrays.copyOfRange(ipkCertData, offset, offset + 1)[0];

            //caPublicKeyIndex = String.format("%02x", unsignedData.caPublicKeyIndex & 0xFF);

            return unsignedDataBuffer;

        } catch (Exception e) {
            throw new IllegalArgumentException("Error reading UPI unsigned data: " + e.getMessage(), e);
        }
    }


    @Override
    public String getCaPublicKeyIndex(byte[] ipkCertData) {
        return String.format("%02x", ipkCertData[7] & 0xFF);
    }

    @Override
    boolean recoverIpkCert(String caPkModulusN, String caPkExponentE, byte[] ipkCertData) {
        try {
            BigInteger n = new BigInteger(caPkModulusN, 16);
            BigInteger e = new BigInteger(caPkExponentE, 16);

            int ipkCertDataLength = ipkCertData.length;
            int caPkModulusNLength = caPkModulusN.length() / 2;

            byte[] unsignedDataBuffer = readUnsignedData(ipkCertData, caPkModulusNLength);
            System.out.println("[Clear] Unsigned Data: " + bytesToHex(unsignedDataBuffer));

            int certOffset = unsignedDataBuffer.length;
            int remainLength = ipkCertDataLength - certOffset;
            if (remainLength % caPkModulusNLength == 0) {
                // Process certificate data
                byte[] certificateDataBuffer = Arrays.copyOfRange(ipkCertData, certOffset, certOffset + caPkModulusNLength);
                System.out.println("[Encrypted] Certificate Data: " + bytesToHex(certificateDataBuffer));

                String certificateDataEncrypted = bytesToHex(certificateDataBuffer);
                BigInteger encryptedNumber = new BigInteger(certificateDataEncrypted, 16);
                BigInteger decryptedNumber = encryptedNumber.modPow(e, n);
                String certificateDataDecrypted = String.format("%0" + (caPkModulusNLength * 2) + "X", decryptedNumber);
                System.out.println("[Decrypted] Certificate Data: " + certificateDataDecrypted);

                // Check certificate data format
                byte[] certificateDataDecryptedBuffer = hexToByte(certificateDataDecrypted);
                if (certificateDataDecryptedBuffer[0] != 0x6A) {
                    throw new IllegalArgumentException("Invalid Recovered Data Header!");
                }
                if (certificateDataDecryptedBuffer[1] != 0x02) {
                    throw new IllegalArgumentException("Invalid Certificate Format!");
                }
                if (certificateDataDecryptedBuffer[certificateDataDecryptedBuffer.length - 1] != (byte) 0xBC) {
                    throw new IllegalArgumentException("Invalid Recovered Data Trailer!");
                }

            } else {
                throw new IllegalArgumentException("The certificate data length does not match with public key length!");
            }
            return true;
        } catch (NumberFormatException nfe) {
            errorMessage = "Invalid format for modulus or exponent: " + nfe.getMessage();
            return false;
        } catch (IllegalArgumentException iae) {
            errorMessage = iae.getMessage();
            return false;
        } catch (Exception e) {
            errorMessage = "An unexpected error occurred: " + e.getMessage();
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

    public static byte[] hexToByte(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
