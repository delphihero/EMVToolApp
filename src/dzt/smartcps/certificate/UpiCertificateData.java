package dzt.smartcps.certificate;

public class UpiCertificateData {
	byte recoveredDataHeader;
    byte certificateFormat;
    byte[] issuerIdentifier;
    byte[] certificateExpirationDate;
    byte[] certificateSerialNumber;
    byte hashAlgorithmIndicator;
    byte issuerPublicKeyAlgorithmIndicator;
    byte issuerPublicKeyModulusLength;
    byte issuerPublicKeyExponentLength;
    byte[] issuerPublicKeyModulusN;
    byte[] hashResult;
    byte recoveredDataTrailer;
}
