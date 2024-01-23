package dzt.smartcps.certificate;

public class MasterCardCertificateData {
	byte recoveredDataHeader;
    byte certificateFormat;
    byte[] issuerIdentificationNumber;
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
