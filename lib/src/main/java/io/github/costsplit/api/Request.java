package io.github.costsplit.api;

public interface Request {

    /// POST: Get user data
    interface UserData {
        String ENDPOINT = "/user";
    }

    /// GET: Complete user creation
    ///
    /// Path params:
    /// - `token`: JWT
    interface VerifyUser {
        String ENDPOINT = "/auth/verify/{token}";
    }

    /// GET: Delete token
    /// DELETE: Delete user account
    ///
    /// Path params:
    /// - `token`: JWT
    interface Logout {
        String ENDPOINT = "/logout/{token}";
    }

    /// PUT: Create group
    /// POST: Get group data
    /// DELETE: Delete group
    ///
    /// Path params:
    /// - `name`: group name
    interface Group {
        String ENDPOINT = "/group/{name}";
    }

    /// POST: Get group invite URL
    ///
    /// Path params:
    /// - name: group name
    interface GroupInvite {
        String ENDPOINT = "/invite/{name}";
    }

    /// PUT: Add user to a group
    ///
    /// Path params:
    /// - `group`: group name
    /// - `email`: email of the user to add
    interface AddToGroup {
        String ENDPOINT = "/group/{group}/{email}";
    }

    /// POST: Start user creation request
    ///
    /// @param name     username
    /// @param email    associated email to which verification code will be sent
    /// @param password password of the account
    record CreateUser(String name, String email, String password) {
        public static final String ENDPOINT = "/auth/create";
    }

    /// POST: Login
    ///
    /// @param email    user email
    /// @param password user password
    record Login(String email, String password) {
        public static final String ENDPOINT = "/auth/login";
    }

    /// POST: Add/Edit purchase
    ///
    /// @param group    working group
    /// @param purchase new purchase
    record Purchase(String group, io.github.costsplit.api.model.Purchase purchase) {
        public static final String ENDPOINT = "/purchase";
    }
}
