import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;

import java.io.File;


public class ManipulatePDF {

    public void setID(String path) {
        try {
            File pdfFile = new File(path);
            PDDocument document = PDDocument.load(pdfFile);

            PDDocumentInformation info = document.getDocumentInformation();

            String str = getRandomString(16);
            String num = getRandomNumber(16);
            info.setCustomMetadataValue("ID", str + "-" + num);

            document.setDocumentInformation(info);
            document.save(pdfFile);
        }
        catch(Exception e) {
            System.out.println("PDF not found or could not be saved!");
        }
    }

    public String getID(String path) {
        try {
            File pdfFile = new File(path);
            PDDocument document = PDDocument.load(pdfFile);

            PDDocumentInformation info = document.getDocumentInformation();
            return info.getCustomMetadataValue("ID");
        }
        catch(Exception e) {
            System.out.println("PDF not found or ID not found!");
            return null;
        }
    }

    private static String getRandomString(int length) {
        // chose a Character random from this String
        String alphabeticString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            // generate a random number between 0 to length
            int index = (int)(alphabeticString.length() * Math.random());

            // add Character one by one in end of sb
            sb.append(alphabeticString.charAt(index));
        }

        return sb.toString();
    }

    private static String getRandomNumber(int length) {
        String out = "";

        for (int i = 0; i < length; i++) {
            out = out + (int) Math.floor(Math.random()*10);
        }

        return out;
    }

}
