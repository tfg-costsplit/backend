import io.github.cdimascio.dotenv.Dotenv;
import io.github.costsplit.app.App;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        var env = Dotenv.load();
        var app = App.Config.builder()
                .host(env.get("CS_HOST"))
                .port(Integer.parseInt(env.get("CS_PORT")))
                .smtpHost(env.get("CS_SMTP_HOST"))
                .smtpPort(Integer.parseInt(env.get("CS_SMTP_PORT")))
                .senderMail(env.get("CS_SENDER_MAIL"))
                .senderPassword(env.get("CS_SENDER_PASSWORD"))
                .isLocal(Boolean.parseBoolean(env.get("CS_LOCAL_MODE")))
                .secret(env.get("CS_SECRET"))
                .build()
                .toApp()
                .start();

        Runtime.getRuntime().addShutdownHook(new Thread(app::stop));
    }
}
