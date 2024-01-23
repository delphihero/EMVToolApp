package dzt.smartcps.certificate;

public class VisaUnsignedData {
	byte header; // 1 byte
    byte[] serviceIdentifier; // 4 bytes
    byte[] issuerIdentifier; // 4 bytes
    byte[] certificateSerialNumber; // 3 bytes
    byte[] certificateExpirationDate; // 2 bytes
    byte issuerPublicKeyModulusRemainderLength; // 1 byte
    byte[] issuerPublicKeyModulusNRemainder; // 0 and maximum value of (NI –NCA+ 36)
    byte issuerPublicKeyExponentLength; // 1 byte
    byte[] issuerPublicKeyExponent; // 1 or 3 bytes
    byte caPublicKeyIndex; // 1 byte
}
