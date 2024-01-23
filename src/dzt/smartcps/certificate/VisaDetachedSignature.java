package dzt.smartcps.certificate;

public class VisaDetachedSignature {
	byte header;
    byte blockFormatCode;
    byte paddingCharacters;
    byte separator;
    byte algorithmIndicator;
    byte[] hashResults;
}
