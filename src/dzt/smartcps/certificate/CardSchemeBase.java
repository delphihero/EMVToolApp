package dzt.smartcps.certificate;

abstract class CardSchemeBase {
	protected String errorMessage;
	public String getErrorMessage() {
		return errorMessage;
	}

	protected String certCaPkModulusN;
	public String getCertCaPkModulusN() {
		return certCaPkModulusN;
	}
	protected String certCaPkExponentE;
	public String getCertCaPkExponentE() {
		return certCaPkExponentE;
	}

	abstract String getCaPublicKeyIndex(byte[] ipkCertData);
	abstract boolean recoverIpkCert(String caPkModulusN, String caPkExponentE, byte[] ipkCertData);


}
