package io.github.costsplit.app;

import io.github.costsplit.api.Request;
import io.javalin.Javalin;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AppTest {

    static Javalin app;
    static Retrofit retrofit;

    @BeforeAll
    static void init() {
        app = App.start();
        retrofit = new Retrofit.Builder()
                .addConverterFactory(JacksonConverterFactory.create())
                .baseUrl("http://localhost:" + app.port() + "/")
                .build();
    }

    @Test
    void testCreateUser() {
        var call = retrofit.create(AppService.class).createUser(new Request.CreateUser("juan", "juan@example.com", "1234"));
        var response = assertDoesNotThrow(call::execute);
        assertTrue(response.isSuccessful());
    }

    public interface AppService {
        @POST(Request.CreateUser.ENDPOINT)
        Call<Void> createUser(@Body Request.CreateUser user);
    }
}
