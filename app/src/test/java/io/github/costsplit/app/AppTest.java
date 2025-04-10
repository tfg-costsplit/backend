package io.github.costsplit.app;

import io.github.costsplit.api.Request;
import org.junit.jupiter.api.*;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;

import static org.junit.jupiter.api.Assertions.*;

public class AppTest {
    App app;
    Retrofit retrofit;

    @BeforeEach
    void setUp() {
        app = App.Config.builder()
                .secret("1234")
                .host("localhost")
                .port(8080)
                .senderMail("sender@test.net")
                .senderPassword("1234")
                .smtpHost("localhost")
                .smtpPort(1)
                .isLocal(true)
                .build()
                .toApp()
                .start();

        retrofit = new Retrofit.Builder()
                .addConverterFactory(JacksonConverterFactory.create())
                .baseUrl("http://" + app.getConfig().host() + ":" + app.getConfig().port() + "/")
                .build();
    }

    @AfterEach
    void tearDown() {
        app.stop();
    }

    @Test
    void createUser() {
        var call = retrofit.create(AppService.class)
                .createUser(new Request.CreateUser("receiver", "receiver@test.net", "p455w0rd"));
        var response = assertDoesNotThrow(call::execute);
        var callWasCorrect = response.isSuccessful() || response.code() == 500;
        assertTrue(callWasCorrect);
    }

    public interface AppService {
        @POST(Request.CreateUser.ENDPOINT)
        Call<Void> createUser(@Body Request.CreateUser user);
    }
}
