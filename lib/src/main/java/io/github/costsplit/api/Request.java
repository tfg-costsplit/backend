package io.github.costsplit.api;

import java.util.UUID;

public sealed interface Request permits Request.CreateGroup, Request.CreateUser, Request.DeleteUser, Request.GetGroupInvite, Request.JoinGroup, Request.Login, Request.Logout {
    String endpoint();

    record CreateUser(String name, String email, String password) implements Request {
        @Override
        public String endpoint() {
            return "user";
        }
    }

    record DeleteUser(long userId, UUID sessionToken) implements Request {
        @Override
        public String endpoint() {
            return "user";
        }
    }

    record Login(String email, String password) implements Request {
        @Override
        public String endpoint() {
            return "login";
        }
    }

    record Logout(long userId, UUID sessionToken) implements Request {
        @Override
        public String endpoint() {
            return "logout";
        }
    }

    record CreateGroup(long userId, String name, UUID sessionToken) implements Request {
        @Override
        public String endpoint() {
            return "group";
        }
    }

    record GetGroupInvite(long groupId, UUID sessionToken) implements Request {
        @Override
        public String endpoint() {
            return "group";
        }
    }

    record JoinGroup(long userId, long groupInvite, UUID sessionToken) implements Request {
        @Override
        public String endpoint() {
            return "group";
        }
    }
}
