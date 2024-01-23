import dzt.smartcps.certificate.CardSchemes;
import dzt.smartcps.certificate.IPKCert;
import dzt.smartcps.certificate.VisaCardScheme;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
public class Main {
    public static void main(String[] args) {

        // Use Paths.get to construct the file path in a platform-independent way




        // Creating an instance of IPKCert with a valid card scheme
        CardSchemes selCardScheme = CardSchemes.UPI;
        IPKCert cert;
        String caPkModulusN;
        switch (selCardScheme) {
            case VISA:
                caPkModulusN = "ACD2B12302EE644F3F835ABD1FC7A6F62CCE48FFEC622AA8EF062BEF6FB8BA8BC68BBF6AB5870EED579BC3973E121303D34841A796D6DCBC41DBF9E52C4609795C0CCF7EE86FA1D5CB041071ED2C51D2202F63F1156C58A92D38BC60BDF424E1776E2BC9648078A03B36FB554375FC53D57C73F5160EA59F3AFC5398EC7B67758D65C9BFF7828B6B82D4BE124A416AB7301914311EA462C19F771F31B3B57336000DFF732D3B83DE07052D730354D297BEC72871DCCF0E193F171ABA27EE464C6A97690943D59BDABB2A27EB71CEEBDAFA1176046478FD62FEC452D5CA393296530AA3F41927ADFE434A2DF2AE3054F8840657A26E0FC617";
                Path visaPath = Paths.get(".", "ipk_cert_files", "VISA", "960097.I94");
                cert = new IPKCert(selCardScheme, visaPath.toString());
                break;
            case MASTERCARD:
                caPkModulusN = "A191CB87473F29349B5D60A88B3EAEE0973AA6F1A082F358D849FDDFF9C091F899EDA9792CAF09EF28F5D22404B88A2293EEBBC1949C43BEA4D60CFD879A1539544E09E0F09F60F065B2BF2A13ECC705F3D468B9D33AE77AD9D3F19CA40F23DCF5EB7C04DC8F69EBA565B1EBCB4686CD274785530FF6F6E9EE43AA43FDB02CE00DAEC15C7B8FD6A9B394BABA419D3F6DC85E16569BE8E76989688EFEA2DF22FF7D35C043338DEAA982A02B866DE5328519EBBCD6F03CDD686673847F84DB651AB86C28CF1462562C577B853564A290C8556D818531268D25CC98A4CC6A0BDFFFDA2DCCA3A94C998559E307FDDF915006D9A987B07DDAEB3B";
                Path mcPath = Paths.get(".", "ipk_cert_files", "MC", "522230-000001.cEF");
                cert = new IPKCert(selCardScheme, mcPath.toString());
                break;
            case UPI:
                caPkModulusN = "BC853E6B5365E89E7EE9317C94B02D0ABB0DBD91C05A224A2554AA29ED9FCB9D86EB9CCBB322A57811F86188AAC7351C72BD9EF196C5A01ACEF7A4EB0D2AD63D9E6AC2E7836547CB1595C68BCBAFD0F6728760F3A7CA7B97301B7E0220184EFC4F653008D93CE098C0D93B45201096D1ADFF4CF1F9FC02AF759DA27CD6DFD6D789B099F16F378B6100334E63F3D35F3251A5EC78693731F5233519CDB380F5AB8C0F02728E91D469ABD0EAE0D93B1CC66CE127B29C7D77441A49D09FCA5D6D9762FC74C31BB506C8BAE3C79AD6C2578775B95956B5370D1D0519E37906B384736233251E8F09AD79DFBE2C6ABFADAC8E4D8624318C27DAF1";
                Path upiPath = Paths.get(".", "ipk_cert_files", "UPI", "016510.I04");
                cert = new IPKCert(selCardScheme, upiPath.toString());
                break;
            default:
                return;
        }

        // Displaying information using the displayInfo method
        cert.displayInfo();

        // Example of using the validate method
        String caPkExponentE = "03";
        boolean recoveryResult = cert.validate(caPkModulusN, caPkExponentE);
        System.out.println("Recovery Result: " + recoveryResult);

        if (!recoveryResult) {
            System.out.println("Error Message: " + cert.getErrorMessage());
        }

    }
}