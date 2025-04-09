package io.github.costsplit.api;

import java.util.UUID;

public sealed interface Request {

    /// POST: Start user creation request
    ///
    /// @param name     username
    /// @param email    associated email to which verification code will be sent
    /// @param password password of the account
    record CreateUser(String name, String email, String password) implements Request {
        public static final String ENDPOINT = "user";
    }

    /// GET: Get user data
    ///
    /// @param sessionToken associated user token
    record UserData(UUID sessionToken) implements Request {
        public static final String ENDPOINT = "user";
    }

    /// POST: Complete user creation
    ///
    /// @param code         verification code sent trough email
    /// @param sessionToken associated session token
    record VerifyUser(long code, UUID sessionToken) implements Request {
        public static final String ENDPOINT = "verify";
    }

    /// POST: Login
    ///
    /// @param email    user email
    /// @param password user password
    record Login(String email, String password) implements Request {
        public static final String ENDPOINT = "user";
    }

    /// GET: Close session
    /// DELETE: Delete user account
    ///
    /// @param sessionToken user session token
    record Logout(UUID sessionToken) implements Request {
        public static final String ENDPOINT = "user";
    }

    /// POST: Create group
    /// GET: Get group data
    /// DELETE: Delete group
    ///
    /// @param groupName    name of the group
    /// @param sessionToken user session token
    record Group(String groupName, UUID sessionToken) implements Request {
        public static final String ENDPOINT = "group";
    }

    /// GET: Get group invite URL
    ///
    /// @param groupName    name of the group for the invite
    /// @param sessionToken user session token
    record GroupInvite(String groupName, UUID sessionToken) implements Request {
        public static final String ENDPOINT = "invite";
    }

    /// PUT: Add user to a group
    ///
    /// @param email        email of the user that we are working with
    /// @param groupName    name of the group that we are working with
    /// @param sessionToken user session token
    record AddToGroup(String email, String groupName, UUID sessionToken) implements Request {
        public static final String ENDPOINT = "group";
    }

    /// POST: Add/Edit purchase
    ///
    /// @param group        working group
    /// @param purchase     new purchase
    /// @param sessionToken user session token
    record Purchase(String group, Purchase purchase, UUID sessionToken) implements Request {
        public static final String ENDPOINT = "purchase";
    }
}
