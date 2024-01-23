package dzt.smartcps.certificate;

public class UpiDetachedSignature {
	byte header;
    byte blockFormatCode;
    byte[] rightPaddingCharacters;
    byte separator;
    byte algorithmIndicator;
    byte[] hashResults;
}
