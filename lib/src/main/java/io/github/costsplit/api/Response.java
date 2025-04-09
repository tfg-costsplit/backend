package io.github.costsplit.api;

import java.util.UUID;

public sealed interface Response {
    record CreateUser(long id, UUID sessionToken) implements Response {}
    record Login(long id, UUID sessionToken) implements Response {}
    record CreateGroup(long groupId) implements Response {}
    record GetGroupInvite(long groupInvite) implements Response {}
}
