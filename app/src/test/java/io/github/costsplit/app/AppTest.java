package io.github.costsplit.app;

import io.github.costsplit.api.Request;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
    void createUser() throws IOException {
        var call = retrofit.create(AppService.class)
                .createUser(new Request.CreateUser("receiver", "receiver@test.net", "p455w0rd"));
        var response = assertDoesNotThrow(call::execute);
        if (response.isSuccessful())
            return;
        try (var errbody = response.errorBody()) {
            assert errbody != null;
            assertEquals("Couldn't send confirmation mail", new String(errbody.bytes(), StandardCharsets.UTF_8));
        }
    }

    interface AppService {
        @POST(Request.CreateUser.ENDPOINT)
        Call<Void> createUser(@Body Request.CreateUser user);
    }
}
