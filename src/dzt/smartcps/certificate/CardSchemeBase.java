package dzt.smartcps.certificate;

abstract class CardSchemeBase {
	protected String errorMessage;
	public String getErrorMessage() {
		return errorMessage;
	}
	abstract boolean recoverIpkCert(String caPkModulusN, String caPkExponentE, byte[] ipkCertData);


}
