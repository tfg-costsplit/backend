package io.github.costsplit.app;

import io.github.costsplit.api.Request;
import org.junit.jupiter.api.*;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.converter.scalars.ScalarsConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Path;

import java.io.IOException;
import java.util.function.Supplier;

import static io.github.costsplit.app.TestHelperKt.*;
import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AppTest {

    static Supplier<String> err(Response<?> res) {
        return () -> {
            try (var err = res.errorBody()) {
                assert err != null;
                return err.string();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }

    public static AppService retrofit() {
        return new Retrofit.Builder()
                .addConverterFactory(ScalarsConverterFactory.create())
                .addConverterFactory(JacksonConverterFactory.create())
                .baseUrl("http://" + getApp().getHost() + ":" + getApp().getPort() + "/")
                .build()
                .create(AppService.class);
    }

    @AfterEach
    void tearDown() {
        reset();
    }

    @Test
    void createUser() {
        withMail();
        var call = getAppService().createUser(new Request.CreateUser("receiver", "receiver@test.net", "p455w0rd"));
        var response = assertDoesNotThrow(call::execute);
        assertTrue(response::isSuccessful, err(response));
    }

    @Test
    void verifyUser() {
        var id = insertUser("receiver@test.net", "1234");
        var token = getApp().genVerificationJwt$app(id);
        var call = getAppService().verifyUser(token);
        var response = assertDoesNotThrow(call::execute);
        assertTrue(response::isSuccessful, err(response));
    }

    @Test
    void login() {
        var mail = "receiver@test.net";
        var pass = "1234";
        insertUser(mail, pass);
        var call = getAppService().login(new Request.Login(mail, pass));
        var response = assertDoesNotThrow(call::execute);
        assertTrue(response::isSuccessful, err(response));
    }

    public interface AppService {
        @POST("/auth/create")
        Call<String> createUser(@Body Request.CreateUser user);

        @GET("/auth/verify/{token}")
        Call<String> verifyUser(@Path("token") String token);

        @POST("/auth/verify")
        Call<String> login(@Body Request.Login credentials);
    }
}
