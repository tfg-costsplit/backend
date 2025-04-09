package io.github.costsplit.api;

import io.github.costsplit.api.model.Purchase;

import java.net.URL;
import java.util.List;

public sealed interface Response {
    record UserData(List<String> groups) implements Response {
    }

    record Login(String token) implements Response {
    }

    record Group(List<Purchase> purchases) implements Response {
    }

    record GroupInvite(URL invite) implements Response {
    }
}
