package io.github.costsplit.api;

public sealed interface Request {

    /// POST: Start user creation request
    ///
    /// @param name     username
    /// @param email    associated email to which verification code will be sent
    /// @param password password of the account
    record CreateUser(String name, String email, String password) implements Request {
        public static final String ENDPOINT = "/auth/create";
    }

    /// GET: Get user data
    ///
    /// @param token user token
    record UserData(String token) implements Request {
        public static final String ENDPOINT = "/user";
    }

    /// POST: Complete user creation
    ///
    /// @param token one time auth token
    record VerifyUser(String token) implements Request {
        public static final String ENDPOINT = "/auth/verify";
    }

    /// POST: Login
    ///
    /// @param email    user email
    /// @param password user password
    record Login(String email, String password) implements Request {
        public static final String ENDPOINT = "/auth/login";
    }

    /// GET: Close session
    /// DELETE: Delete user account
    ///
    /// @param token user token
    record Logout(String token) implements Request {
        public static final String ENDPOINT = "/user";
    }

    /// POST: Create group
    /// GET: Get group data
    /// DELETE: Delete group
    ///
    /// @param groupName name of the group
    /// @param token     user token
    record Group(String groupName, String token) implements Request {
        public static final String ENDPOINT = "/group";
    }

    /// GET: Get group invite URL
    ///
    /// @param groupName name of the group for the invite
    /// @param token     user token
    record GroupInvite(String groupName, String token) implements Request {
        public static final String ENDPOINT = "/invite";
    }

    /// PUT: Add user to a group
    ///
    /// @param email     email of the user that we are working with
    /// @param groupName name of the group that we are working with
    /// @param token     user token
    record AddToGroup(String email, String groupName, String token) implements Request {
        public static final String ENDPOINT = "/group";
    }

    /// POST: Add/Edit purchase
    ///
    /// @param group    working group
    /// @param purchase new purchase
    /// @param token    user token
    record Purchase(String group, Purchase purchase, String token) implements Request {
        public static final String ENDPOINT = "/purchase";
    }
}
