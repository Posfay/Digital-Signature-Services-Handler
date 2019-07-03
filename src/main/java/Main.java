public class Main {

    public static void main(String[] args) {

        ManipulatePDF manipulatePDF = new ManipulatePDF();

        DSSHandler dssHandler = new DSSHandler();

        manipulatePDF.setID("sample.pdf");

        dssHandler.signPDF("sample.pdf", "signedSample2.pdf", "cert.p12", "123456");

        String[] files = new String[4];
        files[0] = "asicSample1.pdf";
        files[1] = "asicSample2.pdf";
        files[2] = "pom.xml";
        files[3] = "managingDSS.iml";
        dssHandler.signAsic(files, "output.asice", "cert.p12", "123456");

//        boolean valid = dssHandler.validateCertificate("cert.p12");
//
//        System.out.println(valid);
    }
}

