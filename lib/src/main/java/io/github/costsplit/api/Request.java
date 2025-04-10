package io.github.costsplit.api;

public interface Request {

    /// POST: Start user creation request
    ///
    /// @param name     username
    /// @param email    associated email to which verification code will be sent
    /// @param password password of the account
    record CreateUser(String name, String email, String password) {
        public static final String ENDPOINT = "/auth/create";
    }

    /// GET: Get user data
    interface UserData {
        String ENDPOINT = "/user";
    }

    /// GET: Complete user creation
    ///
    /// @param token one time auth token
    record VerifyUser(String token) {
        public static final String ENDPOINT = "/auth/verify/{token}";
    }

    /// POST: Login
    ///
    /// @param email    user email
    /// @param password user password
    record Login(String email, String password) {
        public static final String ENDPOINT = "/auth/login";
    }

    /// GET: Close session
    /// DELETE: Delete user account
    interface Logout {
        String ENDPOINT = "/logout";
    }

    /// PUT: Create group
    /// GET: Get group data
    /// DELETE: Delete group
    ///
    /// @param groupName name of the group
    record Group(String groupName) {
        public static final String ENDPOINT = "/group";
    }

    /// GET: Get group invite URL
    ///
    /// @param groupName name of the group for the invite
    record GroupInvite(String groupName) {
        public static final String ENDPOINT = "/invite";
    }

    /// PUT: Add user to a group
    ///
    /// @param email     email of the user that we are working with
    /// @param groupName name of the group that we are working with
    record AddToGroup(String email, String groupName) {
        public static final String ENDPOINT = "/group";
    }

    /// POST: Add/Edit purchase
    ///
    /// @param group    working group
    /// @param purchase new purchase
    record Purchase(String group, Purchase purchase) {
        public static final String ENDPOINT = "/purchase";
    }
}
