package io.github.costsplit.app;

import com.dumbster.smtp.SimpleSmtpServer;
import io.github.costsplit.api.Request;
import org.junit.jupiter.api.*;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Path;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AppTest {
    App.Config.ConfigBuilder appConfigBuilder;
    App app;
    SimpleSmtpServer dumbster;

    @BeforeEach
    void setUp() {
        appConfigBuilder = App.Config.builder()
                .secret("1234")
                .host("localhost")
                .port(8080)
                .senderMail("sender@test.net")
                .senderPassword("1234")
                .smtpHost("localhost")
                .smtpPort(25)
                .isLocal(true);
    }

    App.Config config() {
        return appConfigBuilder.build();
    }

    Retrofit retrofit() {
        if (app == null) {
            app = config().toApp().start();
        }
        var cfg = config();
        return new Retrofit.Builder()
                .addConverterFactory(JacksonConverterFactory.create())
                .baseUrl("http://" + cfg.host() + ":" + cfg.port() + "/")
                .build();
    }

    SimpleSmtpServer dumbster() {
        if (dumbster == null) {
            try {
                dumbster = SimpleSmtpServer.start(SimpleSmtpServer.AUTO_SMTP_PORT);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return dumbster;
    }

    @AfterEach
    void tearDown() {
        if (app != null) app.stop();
        if (dumbster != null) dumbster.close();
        dumbster = null;
        app = null;
    }

    @Test
    @Order(2)
    void createUser() {
        appConfigBuilder.smtpPort(dumbster().getPort());
        var call = retrofit().create(AppService.class)
                .createUser(new Request.CreateUser("receiver", "receiver@test.net", "p455w0rd"));
        var response = assertDoesNotThrow(call::execute);
        assertTrue(response::isSuccessful);
    }

    @Test
    @Order(1)
    void sendMail() {
        var port = dumbster().getPort();
        assertDoesNotThrow(() -> App.sendMail("localhost", port, "sender@test.net", "1234", "receiver@test.net", "Hello", "World"));
        assertEquals(1, dumbster().getReceivedEmails().size());
    }

    @Test
    @Order(3)
    void verifyUser() {
        createUser();
        var matcher = Pattern.compile("https://" + config().host() + ":" + config().port() + "/verify/(\\S+)")
                .matcher(dumbster().getReceivedEmails().getFirst().getBody());
        assertTrue(matcher.find());
        var call = retrofit().create(AppService.class).verifyUser(matcher.group(1));
        var response = assertDoesNotThrow(call::execute);
        assertTrue(response::isSuccessful);
    }

    interface AppService {
        @POST(Request.CreateUser.ENDPOINT)
        Call<Void> createUser(@Body Request.CreateUser user);

        @GET(Request.VerifyUser.ENDPOINT)
        Call<Void> verifyUser(@Path("token") String token);
    }
}
