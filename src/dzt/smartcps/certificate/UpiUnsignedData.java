package dzt.smartcps.certificate;

public class UpiUnsignedData {
	byte header;
    byte[] serviceIdentifier;
    byte[] issuerIdentifier;
    byte[] certificateSerialNumber;
    byte[] certificateExpirationDate;
    byte issuerPublicKeyModulusRemainderLength;
    byte[] issuerPublicKeyModulusNRemainder;
    byte issuerPublicKeyExponentLength;
    byte[] issuerPublicKeyExponent;
    byte caPublicKeyIndex;
}
