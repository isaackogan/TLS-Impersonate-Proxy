// Chrome fingerprint through TIP with OkHttp in CA mode; the CA is imported into a truststore first.
// Run: curl -s http://localhost:8080/ca.pem -o tip-ca.pem && keytool -importcert -noprompt -alias tip -file tip-ca.pem -keystore tip.jks -storepass changeit && java -Djavax.net.ssl.trustStore=tip.jks -Djavax.net.ssl.trustStorePassword=changeit -cp okhttp.jar:okio.jar:kotlin-stdlib.jar ca-java-okhttp-basic.java
// Prints: the JSON the destination returned, including user_agent, ja4 and akamai_hash.
import java.net.InetSocketAddress;
import java.net.Proxy;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Main {
    public static void main(String[] args) throws Exception {
        OkHttpClient client = new OkHttpClient.Builder()
            .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 8080)))
            .build();
        Request request = new Request.Builder()
            .url("https://tls.browserleaks.com/json")
            .header("X-Tip-Browser", "Chrome")
            .header("X-Tip-Os", "Windows")
            .build();
        try (Response response = client.newCall(request).execute()) {
            System.out.println(response.body().string());
        }
    }
}
