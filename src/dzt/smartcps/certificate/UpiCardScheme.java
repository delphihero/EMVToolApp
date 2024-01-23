package dzt.smartcps.certificate;

import java.math.BigInteger;
import java.util.Arrays;

public class UpiCardScheme extends CardSchemeBase {
	UpiUnsignedData unsignedData = new UpiUnsignedData();
    UpiCertificateData certificateData = new UpiCertificateData();
    UpiDetachedSignature detachedSignature = new UpiDetachedSignature();
    String errorMessage;

    byte[] readUnsignedData(byte[] ipkCertData) {
        try {
            byte[] unsignedDataBuffer;
            int offset = 0;  // Starting offset

            byte header = ipkCertData[offset];
            offset += 1;
            unsignedData.header = header;

            unsignedData.serviceIdentifier = Arrays.copyOfRange(ipkCertData, offset, offset + 4);
            offset += 4;

            byte[] issuerIdentificationNumber = Arrays.copyOfRange(ipkCertData, offset, offset + 4);
            offset += 4;
            unsignedData.issuerIdentificationNumber = issuerIdentificationNumber;

            byte[] certificateSerialNumber = Arrays.copyOfRange(ipkCertData, offset, offset + 3);
            offset += 3;
            unsignedData.certificateSerialNumber = certificateSerialNumber;

            byte[] certificateExpirationDate = Arrays.copyOfRange(ipkCertData, offset, offset + 2);
            offset += 2;
            unsignedData.certificateExpirationDate = certificateExpirationDate;

            byte issuerPublicKeyModulusRemainderLength = ipkCertData[offset];
            offset += 1;
            unsignedData.issuerPublicKeyModulusRemainderLength = issuerPublicKeyModulusRemainderLength;

            int len = new BigInteger(new byte[]{issuerPublicKeyModulusRemainderLength}).intValue();
            if (len > 0) {
                byte[] issuerPublicKeyModulusNRemainder = Arrays.copyOfRange(ipkCertData, offset, offset + len);
                offset += len;
                unsignedData.issuerPublicKeyModulusNRemainder = issuerPublicKeyModulusNRemainder;
            }

            byte issuerPublicKeyExponentLength = ipkCertData[offset];
            offset += 1;
            unsignedData.issuerPublicKeyExponentLength = issuerPublicKeyExponentLength;

            len = new BigInteger(new byte[]{issuerPublicKeyExponentLength}).intValue();
            if (len > 0) {
                byte[] issuerPublicKeyExponent = Arrays.copyOfRange(ipkCertData, offset, offset + len);
                offset += len;
                unsignedData.issuerPublicKeyExponent = issuerPublicKeyExponent;
            }

            byte caPublicKeyIndex = ipkCertData[offset];
            offset += 1;
            unsignedData.caPublicKeyIndex = caPublicKeyIndex;

            unsignedDataBuffer = Arrays.copyOfRange(ipkCertData, 0, offset);

            return unsignedDataBuffer;

        } catch (Exception e) {
            throw new IllegalArgumentException("Error reading unsigned data: " + e.getMessage(), e);
        }
    }

    @Override
    boolean recoverIpkCert(String caPkModulusN, String caPkExponentE, byte[] ipkCertData) {
        try {
            BigInteger n = new BigInteger(caPkModulusN, 16);
            BigInteger e = new BigInteger(caPkExponentE, 16);

            int ipkCertDataLength = ipkCertData.length;
            int caPkModulusNLength = caPkModulusN.length() / 2;

            byte[] unsignedDataBuffer = readUnsignedData(ipkCertData);
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

                certOffset += caPkModulusNLength;

                // Process detached signature data
                byte[] detachedSignatureBuffer = Arrays.copyOfRange(ipkCertData, certOffset, certOffset + caPkModulusNLength);
                System.out.println("[Encrypted] Detached Signature Data: " + bytesToHex(detachedSignatureBuffer));

                String detachedSignatureEncrypted = bytesToHex(detachedSignatureBuffer);
                encryptedNumber = new BigInteger(detachedSignatureEncrypted, 16);
                decryptedNumber = encryptedNumber.modPow(e, n);
                String detachedSignatureDecrypted = String.format("%0" + (caPkModulusNLength * 2) + "X", decryptedNumber);
                System.out.println("[Decrypted] Detached Signature Data: " + detachedSignatureDecrypted);

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

                // Check detached signature data format
                byte[] detachedSignatureDecryptedBuffer = hexToByte(detachedSignatureDecrypted);
                if (detachedSignatureDecryptedBuffer[0] != 0x00) {
                    throw new IllegalArgumentException("Invalid Detached Signature Header!");
                }
                if (detachedSignatureDecryptedBuffer[1] != 0x01) {
                    throw new IllegalArgumentException("Invalid Detached Signature Block Format Code!");
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
