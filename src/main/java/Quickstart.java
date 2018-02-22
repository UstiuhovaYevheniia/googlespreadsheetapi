import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.SecurityUtils;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.sheets.v4.Sheets;
import com.google.api.services.sheets.v4.SheetsScopes;
import com.google.api.services.sheets.v4.model.ValueRange;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class Quickstart {

    private static HttpTransport transport;
    private static JacksonFactory jsonFactory;
    private static FileDataStoreFactory dataStoreFactory;
    private static List<String> scopes = Arrays.asList(SheetsScopes.SPREADSHEETS);

    public static void main(String args[]) throws IOException, GeneralSecurityException {
        // The ID of the spreadsheet to retrieve data from.
        String spreadsheetId = "1ZYzssGQpcxH-j3T5LTCuiu2SEJQBPymZt0dCjUsp5Wk"; // TODO: Update placeholder value.

        // The A1 notation of the values to retrieve.
        String range = "A1:C2"; // TODO: Update placeholder value.

        // How values should be represented in the output.
        // The default render option is ValueRenderOption.FORMATTED_VALUE.
        String valueRenderOption = ""; // TODO: Update placeholder value.

        // How dates, times, and durations should be represented in the output.
        // This is ignored if value_render_option is
        // FORMATTED_VALUE.
        // The default dateTime render option is [DateTimeRenderOption.SERIAL_NUMBER].
        String dateTimeRenderOption = ""; // TODO: Update placeholder value.

        Quickstart quickstart = new Quickstart();
        Sheets sheetsService = quickstart.createSheetsService();
        Sheets.Spreadsheets.Values.Get request =
                sheetsService.spreadsheets().values().get(spreadsheetId, range);
//        request.setValueRenderOption(valueRenderOption);
//        request.setDateTimeRenderOption(dateTimeRenderOption);

        ValueRange response = request.execute();

        System.out.println(response);
    }

    public Sheets createSheetsService() throws IOException, GeneralSecurityException {
        HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();

        // TODO: Change placeholder below to generate authentication credentials. See
        // https://developers.google.com/sheets/quickstart/java#step_3_set_up_the_sample
        //
        // Authorize using one of the following scopes:
        //   "https://www.googleapis.com/auth/drive"
        //   "https://www.googleapis.com/auth/drive.file"
        //   "https://www.googleapis.com/auth/drive.readonly"
        //   "https://www.googleapis.com/auth/spreadsheets"
        //   "https://www.googleapis.com/auth/spreadsheets.readonly"
        GoogleCredential credential = getCredentialInstanceFromStream(getClass().getClassLoader().getResourceAsStream("client_secret.json"), scopes);

        return new Sheets.Builder(httpTransport, jsonFactory, credential)
                .setApplicationName("goldbug-testing-tool")
                .build();
    }

    public static GoogleCredential getCredentialInstanceFromStream(InputStream credentialsJSON,
                                                                   List<String> scopes) throws GeneralSecurityException, IOException {

        HashMap result = new ObjectMapper().readValue(
                credentialsJSON, HashMap.class);
        JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
        HttpTransport httpTransport = GoogleNetHttpTransport
                .newTrustedTransport();
        String clientId = (String) result.get("client_id");
        String clientEmail = (String) result.get("client_email");
        String privateKeyPem = (String) result.get("private_key");
        String privateKeyId = (String) result.get("private_key_id");
        PrivateKey privateKey = privateKeyFromPkcs8(privateKeyPem);
        GoogleCredential credential = new GoogleCredential.Builder()
                .setTransport(httpTransport).setJsonFactory(JSON_FACTORY)
                .setServiceAccountId(clientEmail)
                .setServiceAccountScopes(scopes)
                .setServiceAccountPrivateKey(privateKey)
                .setServiceAccountPrivateKeyId(privateKeyId).build();
        return credential;
    }

    private static PrivateKey privateKeyFromPkcs8(String privateKeyPem) throws IOException {
        Reader reader = new StringReader(privateKeyPem);
        PemReader.Section section = PemReader.readFirstSectionAndClose(reader, "PRIVATE KEY");
        if (section == null) {
            throw new IOException("Invalid PKCS8 data.");
        }
        byte[] bytes = section.getBase64DecodedBytes();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        Exception unexpectedException = null;
        try {
            KeyFactory keyFactory = SecurityUtils.getRsaKeyFactory();
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException exception) {
            unexpectedException = exception;
        } catch (InvalidKeySpecException exception) {
            unexpectedException = exception;
        }
        throw new IOException("Unexpected exception reading PKCS data");
    }
}
