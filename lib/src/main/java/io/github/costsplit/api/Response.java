package io.github.costsplit.api;

import io.github.costsplit.api.model.Purchase;

import java.net.URL;
import java.util.List;
import java.util.UUID;

public sealed interface Response {
    record CreateUser(UUID sessionToken) implements Response {
    }

    record UserData(List<String> groups) implements Response {
    }

    record Login(UUID sessionToken) implements Response {
    }

    record Group(List<Purchase> purchases) implements Response {
    }

    record GroupInvite(URL invite) implements Response {
    }
}
